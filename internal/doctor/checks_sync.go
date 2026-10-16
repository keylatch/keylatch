package doctor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/guard/hook"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	keysync "github.com/keylatch/keylatch/internal/sync"
)

// SyncState is what doctor learns about the deploy-secret manifest of the
// repository it runs in. It holds names and counts, never a value.
type SyncState struct {
	// Manifest is the manifest's path; empty when the repository has none.
	Manifest string
	// Unchecked says why drift could not be determined.
	Unchecked string
	// Drift lists every difference from the targets.
	Drift []keysync.Change
	// Unguarded lists the env-file targets the agent guard does not protect.
	Unguarded []string
	// LongLived lists the GitHub targets reached with a long-lived token where
	// a GitHub App connection could mint a short-lived one.
	LongLived []string
}

// brokerCall sends one request to the system broker and decodes the reply.
func brokerCall(ctx context.Context, env llmcontext.Lookup, req brokerapi.Request) (brokerapi.Response, error) {
	sock := paths.BrokerSocket(env)
	if info, err := os.Stat(sock); err != nil || info.Mode()&os.ModeSocket == 0 {
		return brokerapi.Response{}, errors.New("the system broker is not installed")
	}
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", sock)
	if err != nil {
		return brokerapi.Response{}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	b, err := json.Marshal(req)
	if err != nil {
		return brokerapi.Response{}, err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return brokerapi.Response{}, err
	}
	rd := bufio.NewReaderSize(conn, 1<<20)
	line, err := rd.ReadBytes('\n')
	if err != nil {
		return brokerapi.Response{}, err
	}
	var resp brokerapi.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return brokerapi.Response{}, err
	}
	return resp, nil
}

func gitOutput(dir string, args ...string) (string, int) {
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output() //nolint:gosec // fixed binary, arguments built here
	var ee *exec.ExitError
	switch {
	case err == nil:
		return strings.TrimSpace(string(out)), 0
	case errors.As(err, &ee):
		return strings.TrimSpace(string(out)), ee.ExitCode()
	}
	return "", -1
}

// probeSync reads the manifest of the current repository and asks the daemon
// for its drift, without trusting either.
func probeSync(ctx context.Context, env llmcontext.Lookup) SyncState {
	cwd, err := os.Getwd()
	if err != nil {
		return SyncState{}
	}
	l, err := keysync.Load("", cwd, gitOutput)
	if errors.Is(err, keysync.ErrNoManifest) {
		return SyncState{}
	}
	st := SyncState{Manifest: filepath.Join(cwd, keysync.DefaultFile)}
	if err != nil {
		st.Unchecked = err.Error()
		return st
	}
	st.Manifest = filepath.Join(l.Root, keysync.DefaultFile)
	for _, name := range l.Manifest.TargetNames() {
		if t := l.Manifest.Targets[name]; t.Type == keysync.TypeEnvFile && !hook.IsEnvFileName(filepath.Base(t.Path)) {
			st.Unguarded = append(st.Unguarded, t.Path)
		}
	}
	resp, err := brokerCall(ctx, env, brokerapi.Request{Op: brokerapi.OpSyncDrift, Sync: &brokerapi.SyncRequest{
		Manifest: l.Raw, Root: l.Root, Links: l.Links, LinkTeams: l.LinkTeams, EnvKeys: l.EnvKeys,
	}})
	switch {
	case err != nil:
		st.Unchecked = "drift needs the system broker (" + err.Error() + ")"
	case !resp.OK || resp.Sync == nil:
		st.Unchecked = "the daemon refused the drift check: " + resp.Error
	default:
		for _, c := range resp.Sync.Changes {
			if c.Kind != keysync.KindUnchanged {
				st.Drift = append(st.Drift, c)
			}
		}
		for name, kind := range resp.Sync.Credentials {
			if kind == "token" && l.Manifest.Targets[name].Type == keysync.TypeGitHub {
				st.LongLived = append(st.LongLived, name)
			}
		}
		sort.Strings(st.LongLived)
	}
	return st
}

// syncChecks are the doctor rows for deploy-secret sync. probe is replaced in tests.
func syncChecks(env llmcontext.Lookup, probe func(context.Context, llmcontext.Lookup) SyncState) []namedCheck {
	var (
		cached SyncState
		done   bool
	)
	state := func(ctx context.Context) SyncState {
		if !done {
			cached, done = probe(ctx, env), true
		}
		return cached
	}
	row := func(name string, fn func(SyncState) Status) namedCheck {
		return plain("daemon", func(ctx context.Context) Status {
			s := state(ctx)
			st := fn(s)
			if s.Manifest == "" {
				st = Status{OK: true, Skipped: true, Detail: "this repository has no " + keysync.DefaultFile}
			}
			st.Name, st.Section = name, "daemon"
			st.Tags = append(st.Tags, "sync")
			return st
		})
	}
	return []namedCheck{
		row("sync.drift", syncDriftRow),
		row("sync.envfiles", syncEnvFilesRow),
		row("sync.credentials", syncCredentialsRow),
	}
}

func syncDriftRow(s SyncState) Status {
	switch {
	case s.Unchecked != "":
		return Status{OK: true, Warn: true, Detail: "drift was not checked: " + s.Unchecked, Fix: "Run: keylatch sync check"}
	case len(s.Drift) == 0:
		return Status{OK: true, Detail: "the deploy targets match " + filepath.Base(s.Manifest)}
	}
	counts := keysync.Counts(s.Drift)
	names := make([]string, 0, len(s.Drift))
	for _, c := range s.Drift {
		names = append(names, fmt.Sprintf("%s %s/%s/%s", c.Kind, c.Target, c.Environment, c.Name))
	}
	if len(names) > 6 {
		names = append(names[:6], fmt.Sprintf("and %d more", len(s.Drift)-6))
	}
	return Status{
		Detail: fmt.Sprintf("deploy targets drifted from %s: %d add, %d update, %d extra (%s)", filepath.Base(s.Manifest), counts[keysync.KindAdd], counts[keysync.KindUpdate], counts[keysync.KindExtra], strings.Join(names, "; ")),
		Fix:    "Run: keylatch sync diff, then keylatch sync apply",
	}
}

func syncEnvFilesRow(s SyncState) Status {
	if len(s.Unguarded) == 0 {
		return Status{OK: true, Detail: "every env-file target is a name the agent guard protects"}
	}
	return Status{
		OK: true, Warn: true,
		Detail: "env-file targets the agent guard does not recognise as secret files: " + strings.Join(s.Unguarded, ", "),
		Fix:    "Name the file .env, .env.<name> or <name>.env so the guard denies agent reads of it",
	}
}

func syncCredentialsRow(s SyncState) Status {
	if len(s.LongLived) == 0 {
		return Status{OK: true, Detail: "no GitHub target is reached with a long-lived token"}
	}
	return Status{
		OK: true, Warn: true,
		Detail: "GitHub targets are reached with a long-lived token where a GitHub App connection could mint a short-lived one: " + strings.Join(s.LongLived, ", "),
		Fix:    "Connect a GitHub App (keylatch connect github-app) and point the target's credential at it",
	}
}
