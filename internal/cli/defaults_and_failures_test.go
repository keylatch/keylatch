package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/testutil"
)

func TestCCDisconnect_EmptyFlagsFallBackToDefaults(t *testing.T) {
	ccProvider(t, "ccdisc")
	ccConnectNoTest(t, "ccdisc", ccSecret("disc"))

	out, _, err := ccRun(t, "", "disconnect", "ccdisc", "--namespace", "", "--account", "")
	if err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if out != "v ccdisc — disconnected\n" {
		t.Fatalf("out = %q", out)
	}
	if _, err := ccVaultGet(t, "default/ai/ccdisc/api_key"); err == nil {
		t.Fatal("default-namespace secret survived disconnect")
	}
}

func TestCCCall_EmptyNamespaceUsesDefault(t *testing.T) {
	up := ccProvider(t, "ccns")
	secret := ccSecret("ns")
	ccConnectNoTest(t, "ccns", secret)

	out, errOut, err := ccRun(t, "", "call", "ccns", "list-models", "--namespace", "", "--no-daemon-start")
	if err != nil {
		t.Fatalf("call: %v (%s)", err, errOut)
	}
	if !strings.Contains(out, `"data"`) {
		t.Fatalf("out = %q", out)
	}
	if auths, _ := up.seen(); len(auths) != 1 || auths[0] != "Bearer "+secret {
		t.Fatalf("credential from default namespace not used: %q", auths)
	}
}

func TestCCBaseURLFromTemplate(t *testing.T) {
	cases := []struct {
		endpoint string
		want     string
		wantErr  string
	}{
		{"https://api.example.com/v1/models?x=1", "https://api.example.com", ""},
		{"http://127.0.0.1:8080/v1", "http://127.0.0.1:8080", ""},
		{"", "", "no test_strategy endpoint"},
		{"http://[::1", "", "parse endpoint"},
		{"/relative/only", "", "has no host"},
	}
	for _, tc := range cases {
		got, err := baseURLFromTemplate(registry.ConnectionTemplate{TestStrategy: registry.TestStrategy{Endpoint: tc.endpoint}})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: err = %v, want %q", tc.endpoint, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v; want %q", tc.endpoint, got, err, tc.want)
		}
	}
}

func TestCCPushReceiptToUI_UnparseableHostIsSkipped(t *testing.T) {
	sink := ccReceiptSink(t)
	t.Setenv("KEYLATCH_UI_ADDR", "bad host:80")
	pushReceiptToUI(t.Context(), runner.RuntimeReceipt{Provider: "x"})
	select {
	case rr := <-sink:
		t.Fatalf("unexpected push: %+v", rr)
	default:
	}
}

func TestCCTeam_CorruptTeamFile(t *testing.T) {
	testutil.ClearLLMSessionEnv(t)
	withInteractiveStdin(t, true)
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	t.Setenv("KEYLATCH_MEMBER_ID", "m-admin")
	if err := os.WriteFile(filepath.Join(dir, "team.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"team invite:":   {"team", "invite", "--email-hmac", "h"},
		"team remove:":   {"team", "remove", "--id", "m-dev"},
		"team transfer:": {"team", "transfer", "--to", "m-dev"},
		"team role:":     {"team", "role", "--id", "m-dev", "--role", "viewer"},
	}
	for prefix, args := range cases {
		_, _, err := ccRun(t, "", args...)
		if err == nil || !strings.HasPrefix(err.Error(), prefix) || !strings.Contains(err.Error(), "team: parse") {
			t.Errorf("%v: err = %v", args, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "team.json")); string(b) != "{broken" {
		t.Fatalf("corrupt team file rewritten: %q", b)
	}
}

func TestCCTeamRole_SaveFailureLeavesFileUntouched(t *testing.T) {
	ccSkipWithoutPermBits(t)
	ccTeam(t)
	dir := os.Getenv("KEYLATCH_TEAM_DIR")
	before, err := os.ReadFile(filepath.Join(dir, "team.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	actAs(t, "m-admin")

	_, _, err = ccRun(t, "", "team", "role", "--id", "m-view", "--role", "developer")
	if err == nil || !strings.HasPrefix(err.Error(), "team role: team: write") {
		t.Fatalf("err = %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "team.json"))
	if string(after) != string(before) {
		t.Fatal("team file changed despite failed save")
	}
}
