//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/spf13/cobra"
)

// fakeBroker stands in for the daemon: it records requests and answers them.
type fakeBroker struct {
	calls   []brokerapi.Request
	handler func(brokerapi.Request) brokerapi.Response
}

func (f *fakeBroker) Call(r brokerapi.Request) (brokerapi.Response, error) {
	// The caller wipes its buffers when done; keep what was sent.
	r.Value = bytes.Clone(r.Value)
	if r.Target != nil {
		target := *r.Target
		target.Value = bytes.Clone(target.Value)
		r.Target = &target
	}
	f.calls = append(f.calls, r)
	if f.handler != nil {
		if resp := f.handler(r); resp.OK || resp.Code != "" {
			return resp, nil
		}
	}
	if r.Op == brokerapi.OpPresenceBegin {
		return brokerapi.Response{OK: true, Proof: &brokerapi.Proof{ID: strings.Repeat("ab", brokerapi.ProofLen), Digest: r.Target.Digest(), Method: "fake"}}, nil
	}
	return brokerapi.Response{OK: true}, nil
}

func (f *fakeBroker) ops() []brokerapi.Op {
	var out []brokerapi.Op
	for _, c := range f.calls {
		out = append(out, c.Op)
	}
	return out
}

func useFakeBroker(t *testing.T, f *fakeBroker) {
	t.Helper()
	prevInstalled, prevDial, prevRaw := brokerInstalled, dialBroker, dialRawBroker
	brokerInstalled = func(llmcontext.Lookup) bool { return true }
	dialBroker = func(llmcontext.Lookup) (brokerCaller, error) { return f, nil }
	dialRawBroker = dialBroker
	t.Cleanup(func() { brokerInstalled, dialBroker, dialRawBroker = prevInstalled, prevDial, prevRaw })
}

func run(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	cmd.SetContext(context.Background())
	err := cmd.Execute()
	return out.String(), err
}

func stdinPipe(t *testing.T, content string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(content); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func TestSetThroughBroker(t *testing.T) {
	f := &fakeBroker{}
	useFakeBroker(t, f)
	cmd := newSetCmd()
	cmd.SetIn(stdinPipe(t, "the-value\n"))
	out, err := run(t, cmd, "default/ai/openrouter/api_key")
	if err != nil {
		t.Fatalf("set: %v (%s)", err, out)
	}
	if got := f.ops(); len(got) != 2 || got[0] != brokerapi.OpPresenceBegin || got[1] != brokerapi.OpSecretSet {
		t.Fatalf("requests = %v", got)
	}
	set := f.calls[1]
	canonical, err := vault.CanonicalPath("default/ai/openrouter/api_key")
	if err != nil {
		t.Fatal(err)
	}
	if set.Path != canonical || string(set.Value) != "the-value" || set.Proof == "" {
		t.Fatalf("secret.set = %+v, want path %s", set, canonical)
	}
	if !strings.Contains(out, canonical) {
		t.Fatalf("the output must name the canonical path %q: %q", canonical, out)
	}
	if f.calls[0].Target.Digest() != (brokerapi.Request{Op: brokerapi.OpSecretSet, Path: canonical, Value: []byte("the-value")}).Digest() {
		t.Fatal("the presence request must describe exactly the set that follows")
	}
	if !strings.Contains(out, "system broker") {
		t.Fatalf("output = %q", out)
	}
}

func TestSetThroughBrokerRefusals(t *testing.T) {
	f := &fakeBroker{}
	useFakeBroker(t, f)
	cmd := newSetCmd()
	cmd.SetIn(stdinPipe(t, "v\n"))
	if _, err := run(t, cmd, "default/ai/openrouter/api_key", "--owner", "me"); err == nil || !strings.Contains(err.Error(), "--owner") {
		t.Fatalf("a metadata flag the broker does not store = %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatal("a refused invocation must not reach the daemon")
	}

	f.handler = func(r brokerapi.Request) brokerapi.Response {
		if r.Op == brokerapi.OpPresenceBegin {
			return brokerapi.Response{Code: brokerapi.CodePresenceRequired, Error: "polkit refused (exit 126)"}
		}
		return brokerapi.Response{}
	}
	cmd = newSetCmd()
	cmd.SetIn(stdinPipe(t, "v\n"))
	if _, err := run(t, cmd, "default/ai/openrouter/api_key"); err == nil || !strings.Contains(err.Error(), "polkit refused") {
		t.Fatalf("presence refused = %v", err)
	}
	if got := f.ops(); len(got) != 1 {
		t.Fatalf("a refused presence must stop before secret.set: %v", got)
	}

	f.handler = func(r brokerapi.Request) brokerapi.Response {
		if r.Op == brokerapi.OpSecretSet {
			return brokerapi.Response{Code: brokerapi.CodeBadRequest, Error: "not a canonical relative path"}
		}
		return brokerapi.Response{}
	}
	cmd = newSetCmd()
	cmd.SetIn(stdinPipe(t, "v\n"))
	if _, err := run(t, cmd, "default/ai/openrouter/api_key"); err == nil || !strings.Contains(err.Error(), "canonical") {
		t.Fatalf("daemon rejection = %v", err)
	}
	cmd = newSetCmd()
	cmd.SetIn(stdinPipe(t, "\n"))
	if _, err := run(t, cmd, "default/ai/openrouter/api_key"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty value = %v", err)
	}
}

func TestBrokerNotInstalled(t *testing.T) {
	prev := brokerInstalled
	brokerInstalled = func(llmcontext.Lookup) bool { return false }
	defer func() { brokerInstalled = prev }()
	for name, cmd := range map[string]*cobra.Command{
		"adopt":          newBrokerAdoptCmd(),
		"export-to-user": newBrokerExportToUserCmd(),
		"rotate-keys":    newBrokerRotateKeysCmd(),
	} {
		if _, err := run(t, cmd); err == nil || !strings.Contains(err.Error(), "broker install") {
			t.Errorf("%s without a broker = %v", name, err)
		}
	}
	st := brokerDaemonState(llmcontext.DefaultLookup)
	if st.Mode != "in-user" || st.Reachable {
		t.Fatalf("state without a broker = %+v", st)
	}
	var out bytes.Buffer
	renderBrokerDaemon(&out, brokerDaemonStatus{Mode: "in-user"})
	if !strings.Contains(out.String(), "not a boundary") {
		t.Fatalf("in-user rendering = %q", out.String())
	}
}

func TestYAMLPolicyImportThroughBroker(t *testing.T) {
	f := &fakeBroker{}
	useFakeBroker(t, f)
	file := filepath.Join(t.TempDir(), "policy.yaml")
	src := "schema_version: 2\nconnections:\n  app-local:\n    callers:\n      agent: { tiers: [D1, D3], approval: auto }\n"
	if err := os.WriteFile(file, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run(t, newPolicyImportCmd(), file); err != nil {
		t.Fatalf("policy import: %v (%s)", err, out)
	}
	accept := f.calls[len(f.calls)-1]
	body := accept.Files["policy.d/app-local.json"]
	if accept.Op != brokerapi.OpPolicyAccept || accept.Proof == "" || len(accept.Files) != 2 || !strings.Contains(string(body), `"app-local"`) {
		t.Fatalf("policy.accept = %+v", accept)
	}
}

func TestHostBoundedPolicyImportIsRefusedWithABroker(t *testing.T) {
	f := &fakeBroker{}
	useFakeBroker(t, f)
	if _, err := run(t, newPolicyImportCmd(), "--from", "claude-code"); err == nil || !strings.Contains(err.Error(), "system broker") {
		t.Fatalf("--from with a broker = %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused import reached the daemon: %v", f.ops())
	}
}

func TestPolicyImportExportAndAuditHeadThroughBroker(t *testing.T) {
	f := &fakeBroker{}
	useFakeBroker(t, f)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "github.json"), []byte(`{"connection":"github"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, newPolicyImportCmd(), dir)
	if err != nil {
		t.Fatalf("policy import: %v (%s)", err, out)
	}
	accept := f.calls[len(f.calls)-1]
	if accept.Op != brokerapi.OpPolicyAccept || accept.Proof == "" || string(accept.Files["policy.d/github.json"]) != `{"connection":"github"}` || len(accept.Files["policy.json"]) == 0 || len(accept.Files) != 2 {
		t.Fatalf("policy.accept = %+v", accept)
	}
	if _, err := run(t, newPolicyImportCmd(), t.TempDir()); err == nil {
		t.Fatal("an empty directory must be refused")
	}

	f.handler = func(r brokerapi.Request) brokerapi.Response {
		switch r.Op {
		case brokerapi.OpPolicyExport:
			return brokerapi.Response{OK: true, Bundle: &brokerapi.Bundle{Files: map[string][]byte{"policy.json": []byte(`{}`), "policy.d/github.json": []byte(`{"c":1}`)}}}
		case brokerapi.OpAuditHead:
			return brokerapi.Response{OK: true, Head: &brokerapi.AuditHead{Hash: "feedbeef", Events: 9}}
		}
		return brokerapi.Response{}
	}
	dst := filepath.Join(t.TempDir(), "out")
	if out, err := run(t, newPolicyExportCmd(), dst); err != nil || !strings.Contains(out, "2 file(s)") {
		t.Fatalf("policy export: %v (%s)", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "github.json")); string(b) != `{"c":1}` {
		t.Fatalf("exported github.json = %q", b)
	}
	if _, err := run(t, newPolicyExportCmd(), dst); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("export over existing files = %v", err)
	}
	if _, err := run(t, newPolicyExportCmd(), dst, "--force"); err != nil {
		t.Fatalf("export --force: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "policy.bundle")); err != nil {
		t.Fatalf("export must write the signed bundle: %v", err)
	}

	// Importing that directory sends the bundle, which the daemon signs again after presence.
	exportHandler := f.handler
	f.handler = nil
	f.calls = nil
	if out, err := run(t, newPolicyImportCmd(), dst); err != nil || !strings.Contains(out, "bundle of 2 file(s)") {
		t.Fatalf("policy import of a bundle: %v (%s)", err, out)
	}
	imp := f.calls[len(f.calls)-1]
	if imp.Op != brokerapi.OpPolicyImport || imp.Bundle == nil || imp.Proof == "" || len(imp.Bundle.Files) != 2 {
		t.Fatalf("policy.import = %+v", imp)
	}
	f.handler = exportHandler
	if err := os.WriteFile(filepath.Join(dst, "policy.bundle"), []byte("not a bundle"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, newPolicyImportCmd(), dst); err == nil || !strings.Contains(err.Error(), "not a policy bundle") {
		t.Fatalf("a corrupt bundle = %v", err)
	}

	out, err = run(t, newAuditHeadCmd(), "--json")
	if err != nil || !strings.Contains(out, "feedbeef") {
		t.Fatalf("audit head --json: %v (%s)", err, out)
	}
	if out, err = run(t, newAuditHeadCmd()); err != nil || !strings.Contains(out, "seq: 9") {
		t.Fatalf("audit head: %v (%s)", err, out)
	}

	f.handler = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{Code: brokerapi.CodeRefused, Error: "the stored policy is tampered"}
	}
	if _, err := run(t, newPolicyExportCmd(), t.TempDir()); err == nil {
		t.Fatal("a refused export must fail")
	}
	if _, err := run(t, newAuditHeadCmd()); err == nil {
		t.Fatal("a refused audit head must fail")
	}
}

func TestBrokerStatusReportsTheDaemon(t *testing.T) {
	f := &fakeBroker{handler: func(r brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{OK: true, Status: &brokerapi.Status{Version: "1.2.3", KeyID: "abcd", Policy: "signed", Presence: "polkit", Secrets: 4}}
	}}
	useFakeBroker(t, f)
	root := newBrokerCmd()
	root.PersistentFlags().Bool("json", false, "")
	out, err := run(t, root, "status")
	if err != nil || !strings.Contains(out, "mode: broker") || !strings.Contains(out, "master key abcd") || !strings.Contains(out, "4 secret(s)") {
		t.Fatalf("status: %v (%s)", err, out)
	}
	root = newBrokerCmd()
	root.PersistentFlags().Bool("json", false, "")
	out, err = run(t, root, "status", "--json")
	var parsed struct {
		Daemon brokerDaemonStatus `json:"daemon"`
	}
	if err != nil || json.Unmarshal([]byte(out), &parsed) != nil || parsed.Daemon.Mode != "broker" || !parsed.Daemon.Reachable || parsed.Daemon.Secrets != 4 {
		t.Fatalf("status --json: %v (%s)", err, out)
	}

	// An installed broker that does not answer is reported, not hidden.
	prev := dialBroker
	dialBroker = func(llmcontext.Lookup) (brokerCaller, error) { return nil, errors.New("connection refused") }
	defer func() { dialBroker = prev }()
	st := brokerDaemonState(llmcontext.DefaultLookup)
	if st.Mode != "broker" || st.Reachable || !strings.Contains(st.Error, "refused") {
		t.Fatalf("unreachable state = %+v", st)
	}
	var text bytes.Buffer
	renderBrokerDaemon(&text, st)
	if !strings.Contains(text.String(), "not reachable") {
		t.Fatalf("rendering = %q", text.String())
	}
	dialBroker = func(llmcontext.Lookup) (brokerCaller, error) {
		return &fakeBroker{handler: func(brokerapi.Request) brokerapi.Response { return brokerapi.Response{Code: brokerapi.CodeRefused} }}, nil
	}
	if st := brokerDaemonState(llmcontext.DefaultLookup); st.Reachable {
		t.Fatalf("a refusing daemon is not reachable: %+v", st)
	}
}

func TestRotateKeysAndInstallCommands(t *testing.T) {
	f := &fakeBroker{handler: func(r brokerapi.Request) brokerapi.Response {
		if r.Op == brokerapi.OpRotateKeys {
			return brokerapi.Response{OK: true, Status: &brokerapi.Status{KeyID: "feed"}}
		}
		return brokerapi.Response{}
	}}
	useFakeBroker(t, f)
	out, err := run(t, newBrokerRotateKeysCmd())
	if err != nil || !strings.Contains(out, "now feed") {
		t.Fatalf("rotate-keys: %v (%s)", err, out)
	}
	if got := f.ops(); len(got) != 2 || got[1] != brokerapi.OpRotateKeys {
		t.Fatalf("requests = %v", got)
	}

	prev := brokerEuid
	brokerEuid = func() int { return 1000 }
	defer func() { brokerEuid = prev }()
	wantErr := "sudo keylatch broker install"
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		wantErr = "runs on Linux, macOS and Windows only"
	}
	if _, err := run(t, newBrokerInstallCmd()); err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("install without root = %v", err)
	}
}

func TestUserSourceReadsPolicyAndShreds(t *testing.T) {
	cfgDir := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return cfgDir
		}
		return ""
	}
	s := &userSource{cfg: config.Default(), env: env}

	if files, err := s.PolicyFiles(); err != nil || files != nil {
		t.Fatalf("no policy = %v, %v", files, err)
	}
	if head, err := s.AuditHead(); err != nil || head != "" {
		t.Fatalf("no audit log = %q, %v", head, err)
	}
	if n, err := s.RevokeTokens(context.Background()); err != nil || n != 0 {
		t.Fatalf("no token store = %d, %v", n, err)
	}

	policyD := filepath.Join(cfgDir, "policy.d")
	if err := os.MkdirAll(policyD, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"github.json": `{"connection":"github"}`, "readme.txt": "x"} {
		if err := os.WriteFile(filepath.Join(policyD, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := s.PolicyFiles()
	if err != nil || len(files) != 2 || string(files["policy.json"]) != `{"default_deny":true}` {
		t.Fatalf("documents only = %v, %v", files, err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "policy.json"), []byte(`{"default_deny":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if files, _ = s.PolicyFiles(); string(files["policy.json"]) != `{"default_deny":false}` {
		t.Fatalf("policy.json = %q", files["policy.json"])
	}

	// Shred removes the key material and reports what it removed.
	for _, p := range []string{paths.AuditSalt(env), paths.GatewaySigningKey(env), paths.KeyringPath(env), paths.KeyringIdentityPath(env)} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("secret-key-material"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	left := inUserLeftovers(env)
	if len(left) != 4 {
		t.Fatalf("leftovers = %v", left)
	}
	gone, err := s.Shred()
	if err != nil || len(gone) < 4 {
		t.Fatalf("Shred = %v, %v", gone, err)
	}
	if after := inUserLeftovers(env); len(after) != 0 {
		t.Fatalf("after shredding: %v", after)
	}
	if again, err := s.Shred(); err != nil || len(again) != 0 {
		t.Fatalf("a second shred = %v, %v", again, err)
	}
	if ok, err := shredFile(filepath.Join(cfgDir, "never-existed")); ok || err != nil {
		t.Fatalf("shredFile of a missing file = %v, %v", ok, err)
	}
}

func TestShredOverwritesBeforeRemoving(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("AAAAAAAAAAAA"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Keep a second name for the same inode so the overwritten content stays observable.
	alias := path + ".link"
	if err := os.Link(path, alias); err != nil {
		t.Skipf("hard links are not supported here: %v", err)
	}
	if ok, err := shredFile(path); !ok || err != nil {
		t.Fatalf("shredFile = %v, %v", ok, err)
	}
	got, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("A")) || len(got) != 12 {
		t.Fatalf("the file was removed without being overwritten: %q", got)
	}
}

func TestBrokerFailureMapsCodes(t *testing.T) {
	for code, want := range map[string]string{
		brokerapi.CodePresenceRequired: "x: boom",
		brokerapi.CodeRefused:          "x: boom",
		brokerapi.CodeNotFound:         "x: boom",
		brokerapi.CodeBadRequest:       "x: boom",
		brokerapi.CodeUnavailable:      "x: boom",
	} {
		if err := brokerFailure("x", brokerapi.Response{Code: code, Error: "boom"}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s = %v", code, err)
		}
	}
}

func TestLaunchThroughBroker(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "systemd-run")
	script := "#!/bin/sh\nwhile [ \"$1\" != \"--\" ]; do shift; done\nshift\nexec \"$@\"\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	prevRun, prevScope := systemdRunPaths, agentScopePath
	systemdRunPaths = []string{fake}
	dump, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip("no /proc/self/cgroup")
	}
	own := brokerd.ParseCgroup(string(dump))
	agentScopePath = func(int, string) string { return own }
	defer func() { systemdRunPaths, agentScopePath = prevRun, prevScope }()

	f := &fakeBroker{handler: func(r brokerapi.Request) brokerapi.Response {
		if r.Op == brokerapi.OpSessionRegister {
			return brokerapi.Response{OK: true, Session: &brokerapi.SessionInfo{ID: r.Session.ID, Ticket: "ticket-from-the-daemon"}}
		}
		return brokerapi.Response{}
	}}
	useFakeBroker(t, f)

	launch := func(argv ...string) (*cobra.Command, *bytes.Buffer, error) {
		c := &cobra.Command{}
		var out bytes.Buffer
		c.SetOut(&out)
		c.SetErr(&out)
		c.SetIn(strings.NewReader(""))
		c.SetContext(context.Background())
		return c, &out, launchThroughBroker(c, llmcontext.DefaultLookup, argv)
	}

	c, out, err := launch("sh", "-c", "echo ticket=$"+llmcontext.TicketEnv)
	_ = c
	if err != nil || !strings.Contains(out.String(), "ticket=ticket-from-the-daemon") {
		t.Fatalf("launch: %v (%q)", err, out.String())
	}
	if got := f.ops(); len(got) != 2 || got[0] != brokerapi.OpSessionRegister || got[1] != brokerapi.OpSessionEnd {
		t.Fatalf("daemon calls = %v", got)
	}
	reg := f.calls[0].Session
	if len(reg.ID) != 32 || reg.Cgroup != own {
		t.Fatalf("registration = %+v", reg)
	}

	// The harness's exit status is passed through.
	if _, _, err := launch("sh", "-c", "exit 3"); err == nil {
		t.Fatal("a failing harness must fail the launch")
	} else if ce := (*CLIError)(nil); !errors.As(err, &ce) || ce.Code != 3 {
		t.Fatalf("exit status = %v", err)
	}

	// A harness that is not in its registered scope is stopped.
	agentScopePath = func(int, string) string { return "/not/the/scope" }
	if _, _, err := launch("sleep", "30"); err == nil || !strings.Contains(err.Error(), "registered scope") {
		t.Fatalf("a harness outside its scope = %v", err)
	}

	// Refusals from the daemon surface.
	f.handler = func(brokerapi.Request) brokerapi.Response {
		return brokerapi.Response{Code: brokerapi.CodeRefused, Error: "no"}
	}
	if _, _, err := launch("true"); err == nil {
		t.Fatal("a refused registration must fail the launch")
	}
	systemdRunPaths = []string{filepath.Join(dir, "absent")}
	if _, _, err := launch("true"); err == nil || !strings.Contains(err.Error(), "systemd-run") {
		t.Fatalf("no systemd-run = %v", err)
	}
}

func TestVerifyBrokerTicket(t *testing.T) {
	f := &fakeBroker{handler: func(r brokerapi.Request) brokerapi.Response {
		if r.Ticket == "good" {
			return brokerapi.Response{OK: true, Session: &brokerapi.SessionInfo{PID: 77, Start: 88}}
		}
		return brokerapi.Response{Code: brokerapi.CodeRefused, Error: "the ticket is not valid"}
	}}
	useFakeBroker(t, f)
	tk, err := verifyBrokerTicket(llmcontext.DefaultLookup, "good")
	if err != nil || tk.PID != 77 || tk.ProcessStart != 88 {
		t.Fatalf("verify = %+v, %v", tk, err)
	}
	if _, err := verifyBrokerTicket(llmcontext.DefaultLookup, "bad"); !errors.Is(err, llmcontext.ErrTicketInvalid) {
		t.Fatalf("a bad ticket = %v", err)
	}
	if got, err := verifySessionTicket(llmcontext.DefaultLookup, "good"); err != nil || got.PID != 77 {
		t.Fatalf("verifySessionTicket with a broker = %+v, %v", got, err)
	}
}

func TestConfirmScope(t *testing.T) {
	dump, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skip("no /proc/self/cgroup")
	}
	if err := confirmScope(os.Getpid(), brokerd.ParseCgroup(string(dump))); err != nil {
		t.Fatalf("own scope: %v", err)
	}
	if err := confirmScope(os.Getpid(), "/elsewhere"); err == nil {
		t.Fatal("a different scope must fail")
	}
	if err := confirmScope(1<<22, "/x"); err == nil {
		t.Fatal("a missing process must fail")
	}
}
