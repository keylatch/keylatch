package trust

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
)

// trClearLLMEnv makes the process look like a human terminal for the test.
func trClearLLMEnv(t *testing.T) {
	t.Helper()
	for _, s := range llmcontext.Signals {
		t.Setenv(s.EnvKey, "")
	}
	t.Setenv(llmcontext.TicketEnv, "")
}

func trNewRoot() *cobra.Command {
	root := &cobra.Command{Use: "keylatch", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().Bool("json", false, "output in JSON format")
	root.AddGroup(&cobra.Group{ID: "advanced", Title: "Advanced"})
	RegisterCommands(root, "advanced")
	return root
}

func trRun(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := trNewRoot()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return out.String(), errb.String(), err
}

// trNewSharedSecretRoot mounts the shared-secret subcommands without the
// build gate that denies the group, so their own logic can be exercised.
func trNewSharedSecretRoot() *cobra.Command {
	root := &cobra.Command{Use: "keylatch", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().Bool("json", false, "output in JSON format")
	group := &cobra.Command{Use: "shared-secret"}
	group.AddCommand(newSharedSecretCreateCmd(), newSharedSecretRewrapCmd(), newSharedSecretRotateCmd(), newSharedSecretRevealCmd())
	root.AddCommand(group)
	return root
}

func trRunShared(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := trNewSharedSecretRoot()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(append([]string{"shared-secret"}, args...))
	err = root.ExecuteContext(context.Background())
	return out.String(), errb.String(), err
}

func trHome(t *testing.T) string {
	t.Helper()
	trClearLLMEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return home
}

func TestRegisterCommandsAttachesGroups(t *testing.T) {
	root := trNewRoot()
	want := map[string][]string{
		"trust":         {"list", "doctor", "enroll", "challenge", "approve", "revoke", "allowlist"},
		"shared-secret": {"create", "rewrap", "rotate", "reveal"},
	}
	for parent, subs := range want {
		cmd, _, err := root.Find([]string{parent})
		if err != nil || cmd.Name() != parent {
			t.Fatalf("Find(%s) = %v, %v", parent, cmd, err)
		}
		if cmd.GroupID != "advanced" {
			t.Errorf("%s GroupID = %q", parent, cmd.GroupID)
		}
		for _, s := range subs {
			if c, _, err := root.Find([]string{parent, s}); err != nil || c.Name() != s {
				t.Errorf("missing %s %s", parent, s)
			}
		}
	}
}

type trFakeRoot struct{ caps trust.Capability }

func (f *trFakeRoot) ID() string                  { return "fake" }
func (f *trFakeRoot) Type() trust.RootType        { return "fake" }
func (f *trFakeRoot) Has(c trust.Capability) bool { return f.caps&c != 0 }
func (f *trFakeRoot) Wrap(context.Context, []byte) ([]byte, error) {
	return nil, trust.ErrCapabilityUnsupported
}
func (f *trFakeRoot) Unwrap(context.Context, []byte) ([]byte, error) {
	return nil, trust.ErrCapabilityUnsupported
}
func (f *trFakeRoot) Sign(context.Context, []byte) ([]byte, crypto.PublicKey, error) {
	return nil, nil, trust.ErrCapabilityUnsupported
}
func (f *trFakeRoot) Verify(context.Context, []byte, []byte, crypto.PublicKey) error {
	return trust.ErrCapabilityUnsupported
}
func (f *trFakeRoot) RequirePresence(context.Context, string) (trust.PresenceProof, error) {
	return trust.PresenceProof{}, trust.ErrCapabilityUnsupported
}
func (f *trFakeRoot) VerifyPresenceProof(context.Context, trust.PresenceProof) error {
	return trust.ErrCapabilityUnsupported
}
func (f *trFakeRoot) Attest(context.Context) (trust.Attestation, error) {
	return trust.Attestation{}, trust.ErrCapabilityUnsupported
}
func (f *trFakeRoot) Close() error { return nil }

func trRegisterFakes(t *testing.T) {
	t.Helper()
	const ok trust.RootType = "tr_fake_ok"
	const broken trust.RootType = "tr_fake_broken"
	trust.Register(ok, func(trust.RootSpec) (trust.RootOfTrust, error) {
		return &trFakeRoot{caps: trust.CapWrap | trust.CapUserPresence}, nil
	})
	trust.Register(broken, func(trust.RootSpec) (trust.RootOfTrust, error) {
		return nil, trust.ErrRootUnavailable
	})
	t.Cleanup(func() {
		trust.Unregister(ok)
		trust.Unregister(broken)
	})
}

func TestTrustListEmptyRegistry(t *testing.T) {
	trHome(t)
	if len(trust.Available()) != 0 {
		t.Skip("another package registered adapters in this binary")
	}
	out, _, err := trRun(t, "trust", "list")
	if err != nil || strings.TrimSpace(out) != "no root-of-trust adapters registered" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	out, _, err = trRun(t, "trust", "list", "--json")
	if err != nil || strings.TrimSpace(out) != "[]" {
		t.Fatalf("json out=%q err=%v", out, err)
	}
}

func TestTrustListShowsRegisteredTypes(t *testing.T) {
	trHome(t)
	trRegisterFakes(t)

	out, _, err := trRun(t, "trust", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "ROOT TYPE\n---------\n") || !strings.Contains(out, "tr_fake_ok\n") || !strings.Contains(out, "tr_fake_broken\n") {
		t.Fatalf("out = %q", out)
	}

	out, _, err = trRun(t, "trust", "list", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		t.Fatalf("bad json %q: %v", out, err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Type] = true
	}
	if !seen["tr_fake_ok"] || !seen["tr_fake_broken"] {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestTrustDoctorReportsProbeResults(t *testing.T) {
	trHome(t)
	trRegisterFakes(t)

	out, _, err := trRun(t, "trust", "doctor")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "TYPE") || !strings.Contains(out, "wrap,user_presence") || !strings.Contains(out, "unavailable") {
		t.Fatalf("out = %q", out)
	}

	out, _, err = trRun(t, "trust", "doctor", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rep trust.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad json %q: %v", out, err)
	}
	got := map[trust.RootType]trust.ReportRow{}
	for _, r := range rep.Rows {
		got[r.Type] = r
	}
	if r := got["tr_fake_ok"]; !r.Available || strings.Join(r.Capabilities, ",") != "wrap,user_presence" {
		t.Errorf("ok row = %+v", r)
	}
	if r := got["tr_fake_broken"]; r.Available || r.Error != "unavailable" {
		t.Errorf("broken row = %+v", r)
	}
}

func trReadChallenge(t *testing.T, home, id string) trust.Challenge {
	t.Helper()
	path := filepath.Join(home, ".keylatch", "approvals", "apv_"+id+".json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("challenge file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("challenge file mode = %v", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Errorf("approvals dir mode = %v (%v)", dirInfo.Mode().Perm(), err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ch trust.Challenge
	if err := json.Unmarshal(data, &ch); err != nil {
		t.Fatal(err)
	}
	return ch
}

func TestTrustChallengeWritesChallengeFile(t *testing.T) {
	cases := []struct {
		bind string
		want trust.Bind
	}{
		{"command", trust.BindCommand},
		{"cwd", trust.BindCWD},
		{"full", trust.BindFull},
		{"none", trust.BindNone},
		{"bogus", trust.BindNone},
	}
	for _, tc := range cases {
		t.Run(tc.bind, func(t *testing.T) {
			home := trHome(t)
			before := time.Now().UTC()
			out, _, err := trRun(t, "trust", "challenge",
				"--actor", "alice", "--capability", "reveal", "--ttl", "2m",
				"--bind", tc.bind, "--command-hash", "c0ffee", "--cwd-hash", "beef")
			if err != nil {
				t.Fatal(err)
			}
			id := strings.TrimSpace(out)
			if len(id) != 32 {
				t.Fatalf("challenge id = %q", id)
			}
			ch := trReadChallenge(t, home, id)
			if ch.Nonce != id || ch.Actor != "alice" || ch.Capability != "reveal" || ch.Bind != tc.want {
				t.Fatalf("challenge = %+v", ch)
			}
			if ch.CommandHash != "c0ffee" || ch.CwdHash != "beef" {
				t.Fatalf("hashes = %q %q", ch.CommandHash, ch.CwdHash)
			}
			if d := ch.Exp.Sub(before); d < 119*time.Second || d > 121*time.Second {
				t.Fatalf("ttl = %v", d)
			}
		})
	}
}

func TestTrustChallengeDefaults(t *testing.T) {
	home := trHome(t)
	out, _, err := trRun(t, "trust", "challenge", "--ttl", "0s")
	if err != nil {
		t.Fatal(err)
	}
	ch := trReadChallenge(t, home, strings.TrimSpace(out))
	if ch.Capability != "inject" || ch.Bind != trust.BindNone || ch.CommandHash != "" || ch.CwdHash != "" {
		t.Fatalf("challenge = %+v", ch)
	}
	if d := time.Until(ch.Exp); d < 4*time.Minute || d > 5*time.Minute {
		t.Fatalf("zero ttl should default to 5m, got %v", d)
	}
}

func TestTrustChallengeFilesystemErrors(t *testing.T) {
	home := trHome(t)
	if err := os.WriteFile(filepath.Join(home, ".keylatch"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := trRun(t, "trust", "challenge")
	if err == nil || !strings.Contains(err.Error(), "trust challenge: mkdir") {
		t.Fatalf("err = %v", err)
	}

	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	home = trHome(t)
	dir := filepath.Join(home, ".keylatch", "approvals")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, _, err = trRun(t, "trust", "challenge")
	if err == nil || !strings.Contains(err.Error(), "trust challenge: write") {
		t.Fatalf("err = %v", err)
	}
}

func TestTrustApprove(t *testing.T) {
	home := trHome(t)

	_, _, err := trRun(t, "trust", "approve", "doesnotexist")
	if err == nil || !strings.Contains(err.Error(), "challenge not found") || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: err = %v", err)
	}

	dir := filepath.Join(home, ".keylatch", "approvals")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "apv_corrupt.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = trRun(t, "trust", "approve", "corrupt")
	if err == nil || !strings.Contains(err.Error(), "parse challenge") {
		t.Fatalf("corrupt: err = %v", err)
	}

	out, _, err := trRun(t, "trust", "challenge", "--ttl", "-1m")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = trRun(t, "trust", "approve", strings.TrimSpace(out))
	if !errors.Is(err, trust.ErrTokenExpired) {
		t.Fatalf("expired: err = %v", err)
	}

	if _, _, err := trRun(t, "trust", "approve"); err == nil || !strings.Contains(err.Error(), "accepts 1 arg") {
		t.Fatalf("no args: err = %v", err)
	}
}

func TestTrustRevokeAndAllowlist(t *testing.T) {
	trHome(t)
	out, _, err := trRun(t, "trust", "revoke", "root-1")
	if err != nil || out != "root marked as revoked\n" {
		t.Fatalf("revoke out=%q err=%v", out, err)
	}
	if _, _, err := trRun(t, "trust", "revoke"); err == nil {
		t.Fatal("revoke without id should fail")
	}

	out, _, err = trRun(t, "trust", "allowlist", "add", "/usr/lib/opensc-pkcs11.so")
	if err != nil || out != "allowlist add: /usr/lib/opensc-pkcs11.so\n" {
		t.Fatalf("add out=%q err=%v", out, err)
	}
	out, _, err = trRun(t, "trust", "allowlist", "list")
	if err != nil || !strings.HasPrefix(out, "MODULE PATH") {
		t.Fatalf("list out=%q err=%v", out, err)
	}
	out, _, err = trRun(t, "trust", "allowlist", "list", "--json")
	if err != nil || strings.TrimSpace(out) != `{"entries":[]}` {
		t.Fatalf("list json out=%q err=%v", out, err)
	}
}

func TestApprovalDirUnderHome(t *testing.T) {
	home := trHome(t)
	if got := approvalDir(); got != home+"/.keylatch/approvals" {
		t.Fatalf("approvalDir = %q", got)
	}
}
