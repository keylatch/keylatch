package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/migrate"
	"github.com/keylatch/keylatch/internal/presence"
)

const actionMigrateImport presence.Action = "migrate.import"

// Seams the tests replace.
var (
	migrateEnv = func() migrate.Env {
		home, _ := os.UserHomeDir()
		return migrate.Env{Home: home, GOOS: runtime.GOOS, Run: execRunner}
	}
	openMigrateStore = func(ctx context.Context, to string, cfg config.Config, env llmcontext.Lookup) (migrate.Store, error) {
		if to == "broker" {
			return openBrokerImportStore(env)
		}
		cfg.Backend = to
		b, err := dispatch.Select(ctx, cfg, env)
		if err != nil {
			return nil, err
		}
		return backendStore{b}, nil
	}
	migrateNow = time.Now
)

// execRunner runs a tool and returns its standard output. The standard error
// is dropped: a tool can echo a value there.
func execRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output() //nolint:gosec // name and args come from this package's fixed tool table
}

// backendStore adapts a backend to migrate.Store.
type backendStore struct{ b backend.Backend }

func (s backendStore) Get(ctx context.Context, p string) ([]byte, error) {
	v, _, err := s.b.Get(ctx, p)
	if errors.Is(err, backend.ErrNotFound) {
		return nil, migrate.ErrNotFound
	}
	return v, err
}

func (s backendStore) Put(ctx context.Context, p string, v []byte) error {
	return s.b.Set(ctx, p, v, backend.Meta{Path: p})
}

// brokerImportStore sends the whole import to the system broker in one
// presence-approved request. The broker never returns a value, so an item it
// already holds is left as it is.
type brokerImportStore struct {
	c        brokerCaller
	existing map[string]bool
	pending  []brokerapi.Item
}

func openBrokerImportStore(env llmcontext.Lookup) (migrate.Store, error) {
	c, err := brokerClient(env)
	if err != nil {
		return nil, err
	}
	resp, err := c.Call(brokerapi.Request{Op: brokerapi.OpSecretList})
	if err != nil {
		return nil, withExitCodeOperation("migrate import", err)
	}
	if !resp.OK {
		return nil, brokerFailure("migrate import", resp)
	}
	s := &brokerImportStore{c: c, existing: map[string]bool{}}
	for _, e := range resp.Entries {
		s.existing[e.Path] = true
	}
	return s, nil
}

func (s *brokerImportStore) Get(_ context.Context, p string) ([]byte, error) {
	if s.existing[p] {
		return nil, migrate.ErrUnreadable
	}
	return nil, migrate.ErrNotFound
}

func (s *brokerImportStore) Put(_ context.Context, p string, v []byte) error {
	s.pending = append(s.pending, brokerapi.Item{Path: p, Value: bytes.Clone(v)})
	return nil
}

func (s *brokerImportStore) Flush(context.Context) error {
	defer func() {
		for i := range s.pending {
			clear(s.pending[i].Value)
		}
		s.pending = nil
	}()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	resp, err := brokerPrivileged(s.c, "migrate import", brokerapi.Request{Op: brokerapi.OpMigrateImport, Items: s.pending, Nonce: nonce})
	if err != nil {
		return err
	}
	for _, it := range s.pending {
		if resp.MACs[it.Path] != brokerd.KeyedHash(nonce, it.Path, it.Value) {
			return fmt.Errorf("the broker stored %s with a different value", it.Path)
		}
	}
	return nil
}

func readRecoveryPassphrase(c *cobra.Command, label string, fromStdin bool) ([]byte, error) {
	if fromStdin {
		b, err := readFieldFromStdin(c.InOrStdin())
		if err != nil || len(b) == 0 {
			return nil, NewUsageError("migrate: a recovery passphrase is required on stdin")
		}
		return b, nil
	}
	b, err := promptHidden(label)
	if err != nil || len(b) == 0 {
		return nil, NewUsageError("migrate: a recovery passphrase is required")
	}
	return b, nil
}

func writeIndentedJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeOut sends data to "-" (or /dev/stdout) as standard output and to
// anything else as an owner-only file.
func writeOut(c *cobra.Command, dest string, v any) error {
	if dest == "" || dest == "-" || dest == "/dev/stdout" {
		return writeIndentedJSON(c.OutOrStdout(), v)
	}
	var buf bytes.Buffer
	if err := writeIndentedJSON(&buf, v); err != nil {
		return err
	}
	return os.WriteFile(filepath.Clean(dest), buf.Bytes(), 0o600)
}

func newMigrateInventoryCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inventory --map <yaml>",
		Short: "List the secrets a machine holds (names and sources only)",
		Long: `Scan the sources named in a map (.env globs, the Secret Service, the macOS
keychain, gh hosts and password-manager item names) and print a JSON plan of
names, sources and target namespaces. The plan never contains a value; edit it,
then pass it to 'keylatch migrate import'.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			mapFile, _ := c.Flags().GetString("map")
			out, _ := c.Flags().GetString("out")
			data, err := os.ReadFile(filepath.Clean(mapFile))
			if err != nil {
				return NewUsageError("migrate inventory: %v", err)
			}
			m, err := migrate.ParseMap(data)
			if err != nil {
				return NewUsageError("%v", err)
			}
			plan, err := migrate.Inventory(c.Context(), m, migrateEnv())
			if err != nil {
				return withExitCode(exitcode.OperationFailed, err)
			}
			return writeOut(c, out, plan)
		},
	}
	cmd.Flags().String("map", "", "map file (YAML) naming the sources to scan (required)")
	cmd.Flags().String("out", "-", "where to write the plan (- for standard output)")
	_ = cmd.MarkFlagRequired("map")
	return cmd
}

func newMigrateImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import --plan <json> --map <yaml> --to bw|op|broker",
		Short: "Write the planned secrets into a backend",
		Long: `Read each value of a plan from its source and write it into the backend under
the plan's namespace and collection. Importing again writes nothing that is
already there. --dry-run reads and compares but writes nothing.

The plan must match the map it was made from (--map): an item whose source,
reference or path the map would not produce is refused before anything is read.

--manifest-out records a keyed hash per item under a key derived from a
recovery passphrase; 'keylatch migrate verify' and 'keylatch drill restore'
check a backend against it on any host. The import needs your presence.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			planFile, _ := c.Flags().GetString("plan")
			mapFile, _ := c.Flags().GetString("map")
			to, _ := c.Flags().GetString("to")
			dry, _ := c.Flags().GetBool("dry-run")
			manifestOut, _ := c.Flags().GetString("manifest-out")
			stdinPass, _ := c.Flags().GetBool("passphrase-stdin")
			switch to {
			case "bw", "op", "broker":
			default:
				return NewUsageError("migrate import: --to must be bw, op or broker")
			}
			data, err := os.ReadFile(filepath.Clean(planFile))
			if err != nil {
				return NewUsageError("migrate import: %v", err)
			}
			plan, err := migrate.ParsePlan(data)
			if err != nil {
				return NewUsageError("%v", err)
			}
			mapData, err := os.ReadFile(filepath.Clean(mapFile))
			if err != nil {
				return NewUsageError("migrate import: %v", err)
			}
			srcMap, err := migrate.ParseMap(mapData)
			if err != nil {
				return NewUsageError("%v", err)
			}
			if err := migrate.ValidatePlan(srcMap, plan, migrateEnv()); err != nil {
				return NewSecurityBlock("%v", err)
			}
			// A dry run needs no presence, so an agent could use it to run the
			// lookup tools; only file sources are read for an agent session.
			if dry && llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				for _, it := range plan.Items {
					if it.CommandBacked() {
						return NewSecurityBlock("migrate import --dry-run runs %s lookups, which needs a human. Ask the person at the machine to run it in a terminal.", it.Source)
					}
				}
			}
			ctx := c.Context()
			env := llmcontext.DefaultLookup
			opt := migrate.ImportOptions{DryRun: dry}
			if manifestOut != "" {
				pass, err := readRecoveryPassphrase(c, "Recovery passphrase", stdinPass)
				if err != nil {
					return err
				}
				defer clear(pass)
				if opt.KDF, err = migrate.NewKDF(); err != nil {
					return err
				}
				if opt.Key, err = opt.KDF.Key(pass); err != nil {
					return err
				}
			}
			if !dry && to != "broker" {
				if _, err := requirePresence(ctx, actionMigrateImport, "Import %d secret(s) into %s: %s", len(plan.Items), to, describePlan(plan)); err != nil {
					return err
				}
			}
			store, err := openMigrateStore(ctx, to, loadCLIConfig(c), env)
			if err != nil {
				return withExitCode(exitcode.BackendUnavailable, fmt.Errorf("migrate import: %w", err))
			}
			res := migrate.Import(ctx, plan, migrateEnv(), store, opt)
			if res.Manifest != nil && !dry {
				if err := writeOut(c, manifestOut, res.Manifest); err != nil {
					return err
				}
			}
			if err := writeIndentedJSON(c.OutOrStdout(), res); err != nil {
				return err
			}
			if res.Failed > 0 {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("migrate import: %d item(s) failed", res.Failed))
			}
			return nil
		},
	}
	cmd.Flags().String("plan", "", "plan file from 'migrate inventory' (required)")
	cmd.Flags().String("map", "", "the map the plan was made from; the plan may only use its sources (required)")
	cmd.Flags().String("to", "", "target backend: bw, op or broker (required)")
	cmd.Flags().Bool("dry-run", false, "report what would be written; write nothing")
	cmd.Flags().String("manifest-out", "", "write a keyed-hash manifest of the imported items here")
	cmd.Flags().Bool("passphrase-stdin", false, "read the recovery passphrase from standard input")
	_ = cmd.MarkFlagRequired("plan")
	_ = cmd.MarkFlagRequired("map")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

// describePlan lists where each secret is read from and written to, for the
// approval the human gives. It shows at most 25 items; the rest are counted.
func describePlan(p migrate.Plan) string {
	const shown = 25
	parts := make([]string, 0, shown+1)
	for i, it := range p.Items {
		if i == shown {
			parts = append(parts, fmt.Sprintf("and %d more", len(p.Items)-shown))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s) -> %s", it.Ref, it.Source, it.Path))
	}
	return strings.Join(parts, "; ")
}

// checkManifest fetches every item of a manifest from the backend and returns
// the report. It is shared by 'migrate verify' and 'drill restore'.
func checkManifest(c *cobra.Command, manifestFile, to string, stdinPass bool) (migrate.Report, error) {
	data, err := os.ReadFile(filepath.Clean(manifestFile))
	if err != nil {
		return migrate.Report{}, NewUsageError("%v", err)
	}
	m, err := migrate.ParseManifest(data)
	if err != nil {
		return migrate.Report{}, NewUsageError("%v", err)
	}
	pass, err := readRecoveryPassphrase(c, "Recovery passphrase", stdinPass)
	if err != nil {
		return migrate.Report{}, err
	}
	defer clear(pass)
	key, err := m.KDF.Key(pass)
	if err != nil {
		return migrate.Report{}, NewUsageError("%v", err)
	}
	defer clear(key)
	cfg := loadCLIConfig(c)
	if to == "" {
		to = cfg.Backend
	}
	if to == "broker" {
		return migrate.Report{}, NewUsageError("the system broker never returns a value, so a manifest cannot be checked against it; the broker's own adopt check covers its store")
	}
	store, err := openMigrateStore(c.Context(), to, cfg, llmcontext.DefaultLookup)
	if err != nil {
		return migrate.Report{}, withExitCode(exitcode.BackendUnavailable, err)
	}
	rep, err := migrate.Verify(c.Context(), m, key, store, migrateNow)
	if err != nil {
		return migrate.Report{}, withExitCode(exitcode.OperationFailed, err)
	}
	return rep, nil
}

func finishReport(c *cobra.Command, report string, rep migrate.Report) error {
	if err := writeOut(c, report, rep); err != nil {
		return err
	}
	if len(rep.Failed)+len(rep.Missing) > 0 {
		return withExitCode(exitcode.OperationFailed, fmt.Errorf("%d item(s) differ and %d are missing", len(rep.Failed), len(rep.Missing)))
	}
	return nil
}

func newMigrateVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify --manifest <json>",
		Short: "Check a backend against a keyed-hash manifest",
		Long: `Fetch each manifest item from the backend and compare keyed hashes. It needs
the recovery passphrase and backend access, nothing else. The report lists the
count of matching items and the paths of those that differ or are missing.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			manifest, _ := c.Flags().GetString("manifest")
			to, _ := c.Flags().GetString("to")
			stdinPass, _ := c.Flags().GetBool("passphrase-stdin")
			rep, err := checkManifest(c, manifest, to, stdinPass)
			if err != nil {
				return err
			}
			return finishReport(c, "-", rep)
		},
	}
	cmd.Flags().String("manifest", "", "manifest file written by 'migrate import' (required)")
	cmd.Flags().String("to", "", "backend to check (default: the configured backend)")
	cmd.Flags().Bool("passphrase-stdin", false, "read the recovery passphrase from standard input")
	_ = cmd.MarkFlagRequired("manifest")
	return cmd
}
