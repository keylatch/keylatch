package cli

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// cdFakeVendor writes a fake vendor CLI named name into a fresh dir. Each
// invocation appends its argv to calls.log and replays <arg1>-<arg2>.{out,err,code}
// fixtures from the same dir.
func cdFakeVendor(t *testing.T, name string) (bin, dir string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake vendor CLI is a POSIX shell script")
	}
	dir = t.TempDir()
	script := "#!/bin/sh\n" +
		"PATH=/usr/bin:/bin\n" +
		"d='" + dir + "'\n" +
		"printf '%s\\n' \"$*\" >> \"$d/calls.log\"\n" +
		"k=\"$1-$2\"\n" +
		"[ -t 0 ] || cat > \"$d/stdin.$k\"\n" +
		"f=\"$d/$k\"\n" +
		"case \"$k\" in item-create|item-edit|create-item|edit-item) : > \"$d/written\";; esac\n" +
		"[ -f \"$d/written\" ] && [ -f \"$f.after.out\" ] && f=\"$f.after\"\n" +
		"[ -f \"$f.out\" ] && cat \"$f.out\"\n" +
		"[ -f \"$f.err\" ] && cat \"$f.err\" >&2\n" +
		"c=0\n" +
		"[ -f \"$f.code\" ] && c=$(cat \"$f.code\")\n" +
		"exit $c\n"
	bin = filepath.Join(dir, name)
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write fake %s: %v", name, err)
	}
	t.Cleanup(dispatch.ClearCached)
	return bin, dir
}

func cdRespond(t *testing.T, dir, key, stdout, stderr string, code int) {
	t.Helper()
	for ext, body := range map[string]string{".out": stdout, ".err": stderr} {
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, key+ext), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if code != 0 {
		if err := os.WriteFile(filepath.Join(dir, key+".code"), []byte(strconv.Itoa(code)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// cdRespondAfterWrite sets the reply for key once a create or edit call has run.
func cdRespondAfterWrite(t *testing.T, dir, key, stdout string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, key+".after.out"), []byte(stdout), 0o600); err != nil {
		t.Fatal(err)
	}
}

func cdStdin(t *testing.T, dir, key string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "stdin."+key))
	if err != nil {
		t.Fatalf("no stdin recorded for %s: %v", key, err)
	}
	return string(b)
}

func cdCalls(t *testing.T, dir string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "calls.log"))
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func cdFakeSecret() string { return "cd-fake-" + strings.Repeat("v", 12) }

// cdEmptyPath leaves PATH pointing at an empty dir so no vendor CLI resolves.
func cdEmptyPath(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	t.Cleanup(dispatch.ClearCached)
}

func cdAssertNoSecret(t *testing.T, r cdResult, secret string) {
	t.Helper()
	if strings.Contains(r.out, secret) || strings.Contains(r.err, secret) {
		t.Fatalf("secret value leaked into command output: out=%q err=%q", r.out, r.err)
	}
}

func TestOPInit_CreatesItemViaPathLookupWithoutEchoingSecret(t *testing.T) {
	cdIsolate(t)
	_, dir := cdFakeVendor(t, "op")
	t.Setenv("PATH", dir)
	cdRespond(t, dir, "item-get", "", "\"svc\" isn't an item in vault Keylatch", 1)
	cdRespond(t, dir, "item-create", `{"id":"new1"}`, "", 0)

	secret := cdFakeSecret()
	cdRespondAfterWrite(t, dir, "item-get", `{"id":"new1","title":"svc","fields":[{"label":"api_key","value":"`+secret+`"}]}`)
	r := cdExec(t, newOPInitCmd(), strings.NewReader(secret+"\n"), "svc", "--from-stdin")
	if r.e != nil {
		t.Fatalf("op-init: %v (stderr %q)", r.e, r.err)
	}
	if !strings.Contains(r.out, "Pushed svc to 1Password vault Keylatch") {
		t.Fatalf("unexpected output %q", r.out)
	}
	cdAssertNoSecret(t, r, secret)

	calls := cdCalls(t, dir)
	if len(calls) != 3 || !strings.HasPrefix(calls[0], "item get svc --vault=Keylatch") {
		t.Fatalf("expected existence probe, create, read-back, got %q", calls)
	}
	if !strings.HasPrefix(calls[1], "item create") || !strings.Contains(calls[1], "--title=svc") ||
		!strings.Contains(calls[1], "--tags=keylatch,ns:default") {
		t.Fatalf("create call missing expected args: %q", calls[1])
	}
	if strings.Contains(calls[1], secret) {
		t.Fatalf("secret must travel on stdin, not argv: %q", calls[1])
	}
	if tmpl := cdStdin(t, dir, "item-create"); !strings.Contains(tmpl, "api_key") || !strings.Contains(tmpl, secret) {
		t.Fatalf("item template on stdin lacks the field: %q", tmpl)
	}
	if !strings.HasPrefix(calls[2], "item get svc") {
		t.Fatalf("write must be read back, got %q", calls[2])
	}
}

func TestOPInit_EditsExistingItemAndReportsConfiguredVault(t *testing.T) {
	cfgDir := cdIsolate(t)
	bin, dir := cdFakeVendor(t, "op")
	t.Setenv("KEYLATCH_OP_BIN", bin)
	cfg := config.Default()
	cfg.OP = &config.OPConfig{Vault: "Team"}
	if err := config.Save(paths.Config(func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return cfgDir
		}
		return ""
	}), cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	cdRespond(t, dir, "item-get", `{"id":"i1","title":"svc","fields":[{"label":"token","value":"x"}]}`, "", 0)
	cdRespond(t, dir, "item-edit", `{"id":"i1"}`, "", 0)
	cdRespondAfterWrite(t, dir, "item-get", `{"id":"i1","title":"svc","fields":[{"label":"token","value":"`+cdFakeSecret()+`"}]}`)

	r := cdExec(t, newOPInitCmd(), strings.NewReader(cdFakeSecret()+"\n"), "svc", "--from-stdin", "--field", "token")
	if r.e != nil {
		t.Fatalf("op-init: %v (stderr %q)", r.e, r.err)
	}
	if !strings.Contains(r.out, "Pushed svc to 1Password vault Team") {
		t.Fatalf("unexpected output %q", r.out)
	}
	calls := cdCalls(t, dir)
	if len(calls) != 3 || !strings.HasPrefix(calls[1], "item edit svc ") || !strings.Contains(calls[1], "--vault=Team") {
		t.Fatalf("expected edit of existing item in vault Team, got %q", calls)
	}
}

func TestOPInit_VendorFailures(t *testing.T) {
	cases := []struct {
		name     string
		stderr   string
		code     int
		wantErr  string
		wantHint string
	}{
		{"signed out maps to backend unavailable", "You are not currently signed in", 1, "exit 4", "eval $(op signin)"},
		{"other failure surfaces exit status", "boom", 7, "op exited 7", "Error:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdIsolate(t)
			bin, dir := cdFakeVendor(t, "op")
			t.Setenv("KEYLATCH_OP_BIN", bin)
			cdRespond(t, dir, "item-get", "", "item not found", 1)
			cdRespond(t, dir, "item-create", "", tc.stderr, tc.code)

			secret := cdFakeSecret()
			r := cdExec(t, newOPInitCmd(), strings.NewReader(secret), "svc", "--from-stdin")
			if r.e == nil || !strings.Contains(r.e.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", r.e, tc.wantErr)
			}
			if !strings.Contains(r.err, tc.wantHint) {
				t.Fatalf("stderr %q missing %q", r.err, tc.wantHint)
			}
			cdAssertNoSecret(t, r, secret)
		})
	}
}

func TestOPInit_PromptReadsNonTerminalStdin(t *testing.T) {
	cdIsolate(t)
	bin, dir := cdFakeVendor(t, "op")
	t.Setenv("KEYLATCH_OP_BIN", bin)
	cdRespond(t, dir, "item-get", "", "item not found", 1)
	cdRespondAfterWrite(t, dir, "item-get", `{"id":"n","title":"svc","fields":[{"label":"api_key","value":"`+cdFakeSecret()+`"}]}`)

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	secret := cdFakeSecret()
	if _, err := pw.WriteString(secret + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	prev := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() { os.Stdin = prev; _ = pr.Close() })

	r := cdExec(t, newOPInitCmd(), nil, "svc")
	if r.e != nil {
		t.Fatalf("op-init: %v (stderr %q)", r.e, r.err)
	}
	if !strings.Contains(r.out, "Enter secret value for svc.api_key:") {
		t.Fatalf("expected masked prompt, got %q", r.out)
	}
	cdAssertNoSecret(t, r, secret)
	calls := cdCalls(t, dir)
	if len(calls) != 3 || !strings.HasPrefix(calls[1], "item create") {
		t.Fatalf("expected create after prompt, got %q", calls)
	}
}

func TestOPCommands_MissingCLIIsBackendUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH isolation differs on Windows")
	}
	cases := []struct {
		name string
		ctor func() *cobra.Command
		args []string
	}{
		{"op-init", newOPInitCmd, []string{"svc", "--from-stdin"}},
		{"op-list", newOPListCmd, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdIsolate(t)
			cdEmptyPath(t)
			r := cdExec(t, tc.ctor(), nil, tc.args...)
			if r.e == nil || !strings.Contains(r.e.Error(), "exit 4") {
				t.Fatalf("err = %v, want exit 4", r.e)
			}
			if !strings.Contains(r.err, "1Password CLI not available") {
				t.Fatalf("stderr %q missing install hint", r.err)
			}
		})
	}
}

func TestOPList_TableIsValueFree(t *testing.T) {
	cdIsolate(t)
	bin, dir := cdFakeVendor(t, "op")
	t.Setenv("KEYLATCH_OP_BIN", bin)
	secret := cdFakeSecret()
	items := `[{"id":"uuid-1","title":"openai","updated_at":"2026-01-02T03:04:05Z","fields":[{"label":"api_key","value":"` + secret + `"}]},` +
		`{"id":"uuid-2","title":"github","fields":[{"label":"token","value":"` + secret + `"}]}]`
	cdRespond(t, dir, "item-list", items, "", 0)

	r := cdExec(t, newOPListCmd(), nil)
	if r.e != nil {
		t.Fatalf("op-list: %v", r.e)
	}
	for _, want := range []string{"CONNECTION/FIELD", "default/openai/api_key", "2026-01-02T03:04:05Z", "default/github/token"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("output missing %q:\n%s", want, r.out)
		}
	}
	cdAssertNoSecret(t, r, secret)
	if strings.Contains(r.out, "uuid-1") {
		t.Errorf("accessor UUIDs must not be printed:\n%s", r.out)
	}
	if calls := cdCalls(t, dir); len(calls) != 1 || calls[0] != "item list --vault=Keylatch --tags=keylatch --format=json" {
		t.Errorf("unexpected list invocation %q", calls)
	}
}

func TestOPList_Outcomes(t *testing.T) {
	cases := []struct {
		name    string
		stdout  string
		stderr  string
		code    int
		wantOut string
		wantErr string
		errText string
	}{
		{name: "empty vault", stdout: "[]", wantOut: "No Keylatch-managed items found in vault Keylatch"},
		{name: "signed out", stderr: "session expired", code: 1, wantErr: "exit 4", errText: "eval $(op signin)"},
		{name: "vendor failure", stderr: "nope", code: 3, wantErr: "op exited 3", errText: "Error:"},
		{name: "garbage json", stdout: "not json", wantErr: "decode response", errText: "Error:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdIsolate(t)
			bin, dir := cdFakeVendor(t, "op")
			t.Setenv("KEYLATCH_OP_BIN", bin)
			cdRespond(t, dir, "item-list", tc.stdout, tc.stderr, tc.code)
			r := cdExec(t, newOPListCmd(), nil)
			if tc.wantErr == "" {
				if r.e != nil || !strings.Contains(r.out, tc.wantOut) {
					t.Fatalf("err=%v out=%q, want %q", r.e, r.out, tc.wantOut)
				}
				return
			}
			if r.e == nil || !strings.Contains(r.e.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", r.e, tc.wantErr)
			}
			if !strings.Contains(r.err, tc.errText) {
				t.Fatalf("stderr %q missing %q", r.err, tc.errText)
			}
		})
	}
}

func TestBWInit_CreatesItemWithSessionOnlyInEnvironment(t *testing.T) {
	cdIsolate(t)
	bin, dir := cdFakeVendor(t, "bw")
	t.Setenv("KEYLATCH_BW_BIN", bin)
	session := "cd-session-" + strings.Repeat("s", 10)
	t.Setenv("BW_SESSION", session)
	cdRespond(t, dir, "get-item", "", "Not found.", 1)

	secret := cdFakeSecret()
	r := cdExec(t, newBWInitCmd(), strings.NewReader(secret+"\n"), "svc", "--from-stdin")
	if r.e != nil {
		t.Fatalf("bw-init: %v (stderr %q)", r.e, r.err)
	}
	if !strings.Contains(r.out, "Pushed svc to Bitwarden") {
		t.Fatalf("unexpected output %q", r.out)
	}
	cdAssertNoSecret(t, r, secret)

	calls := cdCalls(t, dir)
	for _, c := range calls {
		if strings.Contains(c, "--session") || strings.Contains(c, session) {
			t.Fatalf("BW_SESSION must never be passed on argv: %q", c)
		}
	}
	if len(calls) < 2 || calls[1] != "create item" {
		t.Fatalf("expected get then create, got %q", calls)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cdStdin(t, dir, "create-item")))
	if err != nil {
		t.Fatalf("create payload is not base64: %v", err)
	}
	var item struct {
		Name   string `json:"name"`
		Fields []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			Type  int    `json:"type"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if item.Name != "svc" || len(item.Fields) != 1 || item.Fields[0].Name != "api_key" ||
		item.Fields[0].Value != secret || item.Fields[0].Type != 1 {
		t.Fatalf("unexpected created item: %+v", item)
	}
}

func TestBWInit_EditKeepsExistingFields(t *testing.T) {
	cdIsolate(t)
	bin, dir := cdFakeVendor(t, "bw")
	t.Setenv("KEYLATCH_BW_BIN", bin)
	cdRespond(t, dir, "get-item", `{"id":"abc","name":"svc","type":1,"fields":[{"name":"region","value":"eu","type":0}]}`, "", 0)

	r := cdExec(t, newBWInitCmd(), strings.NewReader("new-value\n"), "svc", "--from-stdin")
	if r.e != nil {
		t.Fatalf("bw-init: %v (stderr %q)", r.e, r.err)
	}
	calls := cdCalls(t, dir)
	if len(calls) < 2 || calls[1] != "edit item abc" {
		t.Fatalf("expected edit of item abc, got %q", calls)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cdStdin(t, dir, "edit-item")))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `"name":"region","value":"eu"`) || !strings.Contains(s, `"name":"api_key","value":"new-value","type":1`) {
		t.Fatalf("edit payload must keep region and add api_key: %s", s)
	}
}

func TestBWInit_Failures(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		server  string
		wantErr string
		errText string
	}{
		{
			name: "locked vault",
			setup: func(t *testing.T, dir string) {
				cdRespond(t, dir, "get-item", "", "Vault is locked.", 1)
				cdRespond(t, dir, "status-", `{"status":"locked"}`, "", 0)
				cdRespond(t, dir, "create-item", "", "Vault is locked.", 1)
			},
			wantErr: "exit 4",
			errText: "set BW_SESSION",
		},
		{
			name: "vendor failure",
			setup: func(t *testing.T, dir string) {
				cdRespond(t, dir, "get-item", "", "Not found.", 1)
				cdRespond(t, dir, "create-item", "", "kaput", 9)
			},
			wantErr: "bw exited 9",
			errText: "Error:",
		},
		{
			name:    "plain http server rejected",
			setup:   func(*testing.T, string) {},
			server:  "http://vault.invalid",
			wantErr: "http://vault.invalid",
			errText: "Error:",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdIsolate(t)
			bin, dir := cdFakeVendor(t, "bw")
			t.Setenv("KEYLATCH_BW_BIN", bin)
			t.Setenv("KEYLATCH_BW_SERVER", tc.server)
			tc.setup(t, dir)
			r := cdExec(t, newBWInitCmd(), strings.NewReader("v"), "svc", "--from-stdin")
			if r.e == nil || !strings.Contains(r.e.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", r.e, tc.wantErr)
			}
			if !strings.Contains(r.err, tc.errText) {
				t.Fatalf("stderr %q missing %q", r.err, tc.errText)
			}
			if tc.server != "" && len(cdCalls(t, dir)) != 0 {
				t.Fatal("bw must not be invoked when the server URL is rejected")
			}
		})
	}
}

func TestBWInit_PromptReadsNonTerminalStdin(t *testing.T) {
	cdIsolate(t)
	bin, dir := cdFakeVendor(t, "bw")
	t.Setenv("KEYLATCH_BW_BIN", bin)
	cdRespond(t, dir, "get-item", "", "Not found.", 1)

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.WriteString("typed\n"); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close()
	prev := os.Stdin
	os.Stdin = pr
	t.Cleanup(func() { os.Stdin = prev; _ = pr.Close() })

	r := cdExec(t, newBWInitCmd(), nil, "svc", "--field", "token")
	if r.e != nil {
		t.Fatalf("bw-init: %v (stderr %q)", r.e, r.err)
	}
	if !strings.Contains(r.out, "Enter secret value for svc.token:") || strings.Contains(r.out, "typed") {
		t.Fatalf("unexpected prompt output %q", r.out)
	}
}

func TestBWList_Outcomes(t *testing.T) {
	secret := cdFakeSecret()
	cases := []struct {
		name    string
		stdout  string
		stderr  string
		code    int
		server  string
		wantOut []string
		wantErr string
		errText string
	}{
		{
			name: "items listed without values",
			stdout: `[{"id":"i1","name":"openai","revisionDate":"2026-02-03T04:05:06.000Z","fields":[{"name":"api_key","value":"` + secret + `","type":1}]},` +
				`{"id":"i2","name":"github","fields":[{"name":"token","value":"` + secret + `","type":1}]}]`,
			wantOut: []string{"CONNECTION/FIELD", "default/openai/api_key", "2026-02-03T04:05:06Z", "default/github/token"},
		},
		{name: "empty", stdout: "[]", wantOut: []string{"No Keylatch-managed items found in Bitwarden"}},
		{name: "locked", stderr: "You are not logged in.", code: 1, wantErr: "exit 4", errText: "set BW_SESSION"},
		{name: "vendor failure", stderr: "x", code: 4, wantErr: "bw exited 4", errText: "Error:"},
		{name: "plain http server", server: "http://bw.invalid", wantErr: "http://bw.invalid", errText: "Error:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdIsolate(t)
			bin, dir := cdFakeVendor(t, "bw")
			t.Setenv("KEYLATCH_BW_BIN", bin)
			t.Setenv("KEYLATCH_BW_SERVER", tc.server)
			cdRespond(t, dir, "list-items", tc.stdout, tc.stderr, tc.code)
			r := cdExec(t, newBWListCmd(), nil)
			cdAssertNoSecret(t, r, secret)
			if tc.wantErr == "" {
				if r.e != nil {
					t.Fatalf("bw-list: %v", r.e)
				}
				for _, w := range tc.wantOut {
					if !strings.Contains(r.out, w) {
						t.Errorf("output missing %q:\n%s", w, r.out)
					}
				}
				return
			}
			if r.e == nil || !strings.Contains(r.e.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", r.e, tc.wantErr)
			}
			if !strings.Contains(r.err, tc.errText) {
				t.Fatalf("stderr %q missing %q", r.err, tc.errText)
			}
		})
	}
}

func TestBWCommands_MissingCLIIsBackendUnavailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH isolation differs on Windows")
	}
	t.Run("bw-init", func(t *testing.T) {
		cdIsolate(t)
		cdEmptyPath(t)
		r := cdExec(t, newBWInitCmd(), nil, "svc", "--from-stdin")
		if r.e == nil || !strings.Contains(r.e.Error(), "exit 4") || !strings.Contains(r.err, "Bitwarden CLI not available") {
			t.Fatalf("err=%v stderr=%q", r.e, r.err)
		}
	})
	t.Run("bw-list", func(t *testing.T) {
		cdIsolate(t)
		cdEmptyPath(t)
		r := cdExec(t, newBWListCmd(), nil)
		if r.e == nil || !strings.Contains(r.e.Error(), "exit 4") || !strings.Contains(r.err, "brew install bitwarden-cli") {
			t.Fatalf("err=%v stderr=%q", r.e, r.err)
		}
	})
}

func TestKeychainCommands_UnavailableOffDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("darwin uses the real login keychain")
	}
	t.Cleanup(dispatch.ClearCached)
	t.Run("init", func(t *testing.T) {
		cdIsolate(t)
		r := cdExec(t, newKeychainInitCmd(), nil, "svc")
		if r.e == nil || !strings.Contains(r.e.Error(), "exit 4") || !strings.Contains(r.err, "keychain backend unavailable") {
			t.Fatalf("err=%v stderr=%q", r.e, r.err)
		}
	})
	t.Run("init verify-acl", func(t *testing.T) {
		cdIsolate(t)
		r := cdExec(t, newKeychainInitCmd(), nil, "--verify-acl")
		if r.e == nil || strings.Contains(r.out, "ACL OK") {
			t.Fatalf("verify-acl must not report OK without a keychain: err=%v out=%q", r.e, r.out)
		}
	})
	for name, mk := range map[string]func() ([]string, func() *cobra.Command){
		"repair-acl": func() ([]string, func() *cobra.Command) { return nil, newKeychainRepairACLCmd },
		"list":       func() ([]string, func() *cobra.Command) { return nil, newKeychainListCmd },
		"clear":      func() ([]string, func() *cobra.Command) { return []string{"svc"}, newKeychainClearCmd },
	} {
		args, ctor := mk()
		t.Run(name, func(t *testing.T) {
			cdIsolate(t)
			r := cdExec(t, ctor(), nil, args...)
			if r.e == nil || !strings.Contains(r.err, "Error:") {
				t.Fatalf("err=%v stderr=%q", r.e, r.err)
			}
			if strings.Contains(r.out, "ACL repaired") || strings.Contains(r.out, "Cleared") {
				t.Fatalf("no success output expected, got %q", r.out)
			}
		})
	}
}

func TestKeychainClear_RequiresService(t *testing.T) {
	r := cdExec(t, newKeychainClearCmd(), nil)
	if r.e == nil {
		t.Fatal("keychain-clear without a service must fail")
	}
}

func TestLoadCLIConfig_FallsBackToDefaultOnBadFile(t *testing.T) {
	dir := cdIsolate(t)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := loadCLIConfig(nil)
	if got.Backend != config.Default().Backend || got.Version != config.Default().Version {
		t.Fatalf("expected default config, got %+v", got)
	}
}
