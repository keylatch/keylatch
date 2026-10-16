package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	keysync "github.com/keylatch/keylatch/internal/sync"
	"github.com/keylatch/keylatch/internal/sync/targets"
)

// syncGit runs git in dir and returns its output and exit status. Tests
// replace it.
var syncGit = func(dir string, args ...string) (string, int) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // fixed binary, arguments built here
	out, err := cmd.Output()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return strings.TrimSpace(string(out)), 0
	case errors.As(err, &ee):
		return strings.TrimSpace(string(out)), ee.ExitCode()
	}
	return "", -1
}

// syncBuildHook lets tests swap the target clients of a local run.
var syncBuildHook func(*targets.BuildOptions)

// syncInput is a manifest read from disk with what only the client can see.
type syncInput struct {
	root     string
	manifest keysync.Manifest
	req      brokerapi.SyncRequest
}

func loadSync(c *cobra.Command) (*syncInput, error) {
	file, _ := c.Flags().GetString("file")
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	l, err := keysync.Load(file, cwd, syncGit)
	if err != nil {
		return nil, NewUsageError("%v", err)
	}
	return &syncInput{root: l.Root, manifest: l.Manifest, req: brokerapi.SyncRequest{
		Manifest: l.Raw, Root: l.Root, Links: l.Links, LinkTeams: l.LinkTeams, EnvKeys: l.EnvKeys,
	}}, nil
}

func newSyncCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Keep deploy secrets in step with the connections they come from",
		Long: `Keep Vercel environment variables, GitHub Actions secrets and local env files in
step with the connections they come from, as declared in keylatch.sync.yaml at
the repository root. The daemon reads each value and sends it to the target;
no value passes through this process, your shell or an agent session.

  check   validate the manifest (no network)
  diff    what apply would write: names, targets, environments, reasons
  drift   the same, exit 1 on any difference; for CI and doctor
  apply   write the differences (needs your presence)
  rotate  write a rotated source to its targets, verify, then retire the old value`,
	}
	cmd.PersistentFlags().String("file", "", "manifest path (default: keylatch.sync.yaml at the repository root)")
	cmd.AddCommand(newSyncCheckCmd(), newSyncDiffCmd(), newSyncDriftCmd(), newSyncApplyCmd(), newSyncRotateCmd())
	return cmd
}

func newSyncCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Validate the manifest without network access",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			in, err := loadSync(c)
			if err != nil {
				return err
			}
			if asJSON, _ := c.Flags().GetBool("json"); asJSON {
				return writeIndentedJSON(c.OutOrStdout(), map[string]any{"ok": true, "targets": len(in.manifest.Targets), "vars": len(in.manifest.Vars)})
			}
			fmt.Fprintf(c.OutOrStdout(), "ok: %d target(s), %d variable(s)\n", len(in.manifest.Targets), len(in.manifest.Vars))
			return nil
		},
	}
	cmd.Flags().Bool("json", false, "print JSON")
	return cmd
}

// syncRun sends a sync request to the system broker. Diff and drift fall back
// to a local run, for a human with no broker, that never reads a value.
func syncRun(c *cobra.Command, in *syncInput, op brokerapi.Op, req brokerapi.SyncRequest, files []*os.File) (brokerapi.Response, error) {
	env := llmcontext.DefaultLookup
	if !brokerInstalled(env) {
		if op != brokerapi.OpSyncDiff && op != brokerapi.OpSyncDrift {
			return brokerapi.Response{}, NewUsageError("sync %s needs the system broker: the daemon reads the values and writes the targets, so they never pass through this process. Install it with 'sudo keylatch broker install'", strings.TrimPrefix(string(op), "sync."))
		}
		return syncLocal(c, in, req)
	}
	bc, err := brokerClient(env)
	if err != nil {
		return brokerapi.Response{}, err
	}
	r := brokerapi.Request{Op: op, Sync: &req}
	if !brokerapi.Privileged(op) {
		resp, err := bc.Call(r)
		if err != nil {
			return resp, withExitCodeOperation("sync", err)
		}
		if !resp.OK {
			return resp, brokerFailure("sync", resp)
		}
		return resp, nil
	}
	return brokerPrivilegedFiles(bc, "sync", r, files)
}

// brokerFileCaller is a broker connection that can send file descriptors.
type brokerFileCaller interface {
	CallWithFiles(brokerapi.Request, []*os.File) (brokerapi.Response, error)
}

// brokerPrivilegedFiles is brokerPrivileged for a request followed by file
// descriptors. The presence step carries none: the human approves the request
// the descriptors belong to.
func brokerPrivilegedFiles(c brokerCaller, op string, req brokerapi.Request, files []*os.File) (brokerapi.Response, error) {
	if len(files) == 0 {
		return brokerPrivileged(c, op, req)
	}
	fc, ok := c.(brokerFileCaller)
	if !ok {
		return brokerapi.Response{}, withExitCode(exitcode.OperationFailed, errors.New("this connection cannot pass file descriptors"))
	}
	proven, err := brokerd.Prove(c, req)
	if err != nil {
		return brokerapi.Response{}, NewSecurityBlock("%s: %v", op, err)
	}
	resp, err := fc.CallWithFiles(proven, files)
	if err != nil {
		return resp, withExitCodeOperation(op, err)
	}
	if !resp.OK {
		return resp, brokerFailure(op, resp)
	}
	return resp, nil
}

// syncLocal compares the manifest with the targets in this process, for a
// human with no broker. It never reads a source value, so it reports names,
// environments and types only.
func syncLocal(c *cobra.Command, in *syncInput, req brokerapi.SyncRequest) (brokerapi.Response, error) {
	env := llmcontext.DefaultLookup
	if llmcontext.IsLLMSession(env) {
		return brokerapi.Response{}, NewSecurityBlock("sync: this session belongs to an agent and the system broker is not installed; the target credentials can only be read by the broker or by you in a terminal")
	}
	credential := func(ctx context.Context, connection string) (string, error) {
		b, err := dispatch.Select(ctx, loadCLIConfig(c), env)
		if err != nil {
			return "", withExitCode(exitcode.BackendUnavailable, err)
		}
		entries, err := b.List(ctx, "")
		if err != nil {
			return "", err
		}
		have := make([]string, len(entries))
		for i, e := range entries {
			have[i] = e.Path
		}
		p, err := keysync.FindPath(have, connection, keysync.CredentialFields)
		if err != nil {
			return "", err
		}
		v, _, err := b.Get(ctx, p)
		if err != nil {
			return "", err
		}
		defer clear(v)
		return strings.TrimSpace(string(v)), nil
	}
	opts := targets.BuildOptions{
		Credential: credential, Links: req.Links, LinkTeams: req.LinkTeams, Root: req.Root, EnvKeys: req.EnvKeys,
	}
	if syncBuildHook != nil {
		syncBuildHook(&opts)
	}
	clients, err := targets.Build(in.manifest, opts)
	if err != nil {
		return brokerapi.Response{}, NewUsageError("%v", err)
	}
	eng := &keysync.Engine{Manifest: in.manifest, Targets: clients}
	changes, err := eng.Diff(c.Context(), false)
	if err != nil {
		return brokerapi.Response{}, withExitCode(exitcode.OperationFailed, err)
	}
	return brokerapi.Response{OK: true, Sync: &brokerapi.SyncResult{Changes: changes, Drift: keysync.Drifted(changes)}}, nil
}

func printChanges(c *cobra.Command, changes []keysync.Change, asJSON, all bool) error {
	counts := keysync.Counts(changes)
	if asJSON {
		if changes == nil {
			changes = []keysync.Change{}
		}
		return writeIndentedJSON(c.OutOrStdout(), map[string]any{"changes": changes, "counts": counts, "drift": keysync.Drifted(changes)})
	}
	tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
	for _, ch := range changes {
		if ch.Kind == keysync.KindUnchanged && !all {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", ch.Kind, ch.Target, ch.Environment, ch.Name, ch.Reason)
	}
	_ = tw.Flush()
	fmt.Fprintf(c.OutOrStdout(), "%d add, %d update, %d extra, %d unchanged\n", counts[keysync.KindAdd], counts[keysync.KindUpdate], counts[keysync.KindExtra], counts[keysync.KindUnchanged])
	return nil
}

func newSyncDiffCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show what apply would write (names, targets, environments, reasons)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			in, err := loadSync(c)
			if err != nil {
				return err
			}
			prune, _ := c.Flags().GetBool("prune")
			asJSON, _ := c.Flags().GetBool("json")
			all, _ := c.Flags().GetBool("all")
			resp, err := syncRun(c, in, brokerapi.OpSyncDiff, in.req, nil)
			if err != nil {
				return err
			}
			changes := resp.Sync.Changes
			if !prune {
				kept := changes[:0:0]
				for _, ch := range changes {
					if ch.Kind != keysync.KindExtra {
						kept = append(kept, ch)
					}
				}
				changes = kept
			}
			return printChanges(c, changes, asJSON, all)
		},
	}
	cmd.Flags().Bool("prune", false, "include the names apply --prune would delete")
	cmd.Flags().Bool("json", false, "print JSON")
	cmd.Flags().Bool("all", false, "include unchanged entries")
	return cmd
}

func newSyncDriftCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drift",
		Short: "Report missing, extra and differing names; exit 1 on drift",
		Long: `Compare the manifest with the targets and report missing, extra and differing
names. No value is read or returned, and no backend session is needed when the
system broker is installed. Exits 1 when anything differs, so CI and
'keylatch doctor' can use it.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			in, err := loadSync(c)
			if err != nil {
				return err
			}
			asJSON, _ := c.Flags().GetBool("json")
			resp, err := syncRun(c, in, brokerapi.OpSyncDrift, in.req, nil)
			if err != nil {
				return err
			}
			if err := printChanges(c, resp.Sync.Changes, asJSON, false); err != nil {
				return err
			}
			if keysync.Drifted(resp.Sync.Changes) {
				return reported(exitcode.UserError, errors.New("drift"))
			}
			return nil
		},
	}
	cmd.Flags().Bool("json", false, "print JSON")
	return cmd
}

// openEnvFiles prepares the descriptors for the env-file targets named: the
// existing file read-only (the null device when there is none) and a new
// owner-only file in the same directory. commit renames each over its target.
func openEnvFiles(in *syncInput, names []string) (files []*os.File, commit func() error, abort func(), err error) {
	type pending struct{ tmp, target string }
	var made []pending
	abort = func() {
		for _, f := range files {
			_ = f.Close()
		}
		for _, p := range made {
			_ = os.Remove(p.tmp)
		}
	}
	for _, name := range names {
		target := filepath.Join(in.root, filepath.FromSlash(in.manifest.Targets[name].Path))
		existing, oerr := os.Open(target) //nolint:gosec // G304: the path was validated against the repository
		if errors.Is(oerr, os.ErrNotExist) {
			existing, oerr = os.Open(os.DevNull)
		}
		if oerr != nil {
			abort()
			return nil, nil, nil, oerr
		}
		files = append(files, existing)
		tmp, terr := os.CreateTemp(filepath.Dir(target), ".keylatch-sync-*")
		if terr != nil {
			abort()
			return nil, nil, nil, terr
		}
		if terr := tmp.Chmod(0o600); terr != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
			abort()
			return nil, nil, nil, terr
		}
		files = append(files, tmp)
		made = append(made, pending{tmp.Name(), target})
	}
	commit = func() error {
		for _, p := range made {
			if err := os.Rename(p.tmp, p.target); err != nil {
				return err
			}
		}
		return nil
	}
	return files, commit, abort, nil
}

func envFileTargets(in *syncInput, only func(keysync.Var) bool) []string {
	var out []string
	for _, name := range in.manifest.TargetNames() {
		if in.manifest.Targets[name].Type != keysync.TypeEnvFile {
			continue
		}
		for _, v := range in.manifest.Vars {
			if _, ok := v.To[name]; ok && only(v) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

func printEntries(c *cobra.Command, entries []keysync.Entry, asJSON bool) error {
	if asJSON {
		if entries == nil {
			entries = []keysync.Entry{}
		}
		return writeIndentedJSON(c.OutOrStdout(), map[string]any{"entries": entries})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Target != entries[j].Target {
			return entries[i].Target < entries[j].Target
		}
		return entries[i].Name < entries[j].Name
	})
	tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
	for _, en := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", en.Outcome, en.Target, en.Environment, en.Name, en.Error)
	}
	return tw.Flush()
}

func newSyncApplyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Write the differences to the targets (needs your presence)",
		Long: `Write every add and update of the manifest to its target. The daemon reads each
value and sends it; an env file is written by the daemon through descriptors you
pass and renamed into place by this command, so the value never enters this
process. --prune also deletes the names the manifest does not list. The
approval prompt lists the counts per target and the names, never a value.
A second apply writes nothing.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := requireHumanSync("apply"); err != nil {
				return err
			}
			in, err := loadSync(c)
			if err != nil {
				return err
			}
			prune, _ := c.Flags().GetBool("prune")
			asJSON, _ := c.Flags().GetBool("json")
			req := in.req
			req.Prune = prune
			envs := envFileTargets(in, func(keysync.Var) bool { return true })
			files, commit, abort, err := openEnvFiles(in, envs)
			if err != nil {
				return withExitCode(exitcode.OperationFailed, err)
			}
			req.EnvFiles = envs
			resp, runErr := syncRun(c, in, brokerapi.OpSyncApply, req, files)
			if runErr != nil {
				abort()
				if resp.Sync != nil {
					_ = printEntries(c, resp.Sync.Entries, asJSON)
				}
				return runErr
			}
			for _, f := range files {
				_ = f.Close()
			}
			if err := commit(); err != nil {
				abort()
				return withExitCode(exitcode.OperationFailed, err)
			}
			if err := printEntries(c, resp.Sync.Entries, asJSON); err != nil {
				return err
			}
			for _, en := range resp.Sync.Entries {
				if en.Outcome == keysync.OutcomeFailed {
					return reported(exitcode.OperationFailed, errors.New("some entries failed"))
				}
			}
			return nil
		},
	}
	cmd.Flags().Bool("prune", false, "delete the names the manifest does not list")
	cmd.Flags().Bool("json", false, "print JSON")
	return cmd
}

func newSyncRotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate <name>",
		Short: "Write a rotated source to its targets, verify them, then retire the old value",
		Long: `Rotate a variable after its source connection holds the new value. The daemon
writes the new value to every target of the variable, verifies each (a read-back
where the target hands values back, the target's update time, then the variable's
verify request), and only then retires the previous value. If any target fails
verification the previous value is written back and the rotation stops. It
refuses when no earlier value is recorded unless --no-rollback is given. It
needs your presence.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := requireHumanSync("rotate " + args[0]); err != nil {
				return err
			}
			in, err := loadSync(c)
			if err != nil {
				return err
			}
			target, _ := c.Flags().GetString("target")
			keepOld, _ := c.Flags().GetDuration("keep-old")
			noRollback, _ := c.Flags().GetBool("no-rollback")
			asJSON, _ := c.Flags().GetBool("json")
			if keepOld < 0 || keepOld > 24*time.Hour {
				return NewUsageError("sync rotate: --keep-old must be between 0 and 24h")
			}
			req := in.req
			req.Name, req.Target, req.KeepOldSeconds, req.NoRollback = args[0], target, int64(keepOld/time.Second), noRollback
			envs := envFileTargets(in, func(v keysync.Var) bool { return v.Name == args[0] })
			if target != "" {
				envs = filterString(envs, target)
			}
			files, commit, abort, err := openEnvFiles(in, envs)
			if err != nil {
				return withExitCode(exitcode.OperationFailed, err)
			}
			req.EnvFiles = envs
			resp, runErr := syncRun(c, in, brokerapi.OpSyncRotate, req, files)
			if resp.Sync != nil {
				_ = printEntries(c, resp.Sync.Entries, asJSON)
			}
			if runErr != nil {
				abort()
				return runErr
			}
			for _, f := range files {
				_ = f.Close()
			}
			if err := commit(); err != nil {
				abort()
				return withExitCode(exitcode.OperationFailed, err)
			}
			return nil
		},
	}
	cmd.Flags().String("target", "", "rotate at one target only")
	cmd.Flags().Duration("keep-old", 0, "how long to keep the previous value after every target verified (up to 24h)")
	cmd.Flags().Bool("no-rollback", false, "rotate although no earlier value is recorded to restore on failure")
	cmd.Flags().Bool("json", false, "print JSON")
	return cmd
}

// requireHumanSync refuses an agent session before anything is read. The
// message names the command for the human to run.
func requireHumanSync(what string) error {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return NewSecurityBlock("keylatch sync %s writes secrets to deploy targets and needs a human. Ask the person at the machine to run it in a terminal: keylatch sync %s", what, what)
	}
	return nil
}

func filterString(list []string, keep string) []string {
	var out []string
	for _, s := range list {
		if s == keep {
			out = append(out, s)
		}
	}
	return out
}
