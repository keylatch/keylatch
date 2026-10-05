package cli

import (
	"encoding/json"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

func TestCCStatus_GatewayAndLLMSessionReporting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("liveness probe uses signal 0, which Windows does not support")
	}
	ccEnv(t)
	pidPath := os.Getenv("KEYLATCH_GATEWAY_PID")

	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatalf("write pid: %v", err)
	}
	t.Setenv("CODEX_SANDBOX", "1")

	out, _, err := ccRun(t, "", "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "running on :7878") {
		t.Errorf("gateway with a live pid must show running:\n%s", out)
	}
	if !strings.Contains(out, "active — CODEX_SANDBOX") {
		t.Errorf("LLM session must be reported with its signal:\n%s", out)
	}

	jsonOut, _, err := ccRun(t, "", "status", "--json")
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var st struct {
		Gateway struct {
			Running bool   `json:"running"`
			PID     int    `json:"pid"`
			Address string `json:"address"`
		} `json:"gateway"`
		LLMSession bool `json:"llm_session"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &st); err != nil {
		t.Fatalf("json: %v", err)
	}
	if !st.Gateway.Running || st.Gateway.PID != os.Getpid() || st.Gateway.Address != ":7878" || !st.LLMSession {
		t.Fatalf("status json = %+v", st)
	}
}

func TestCCDetectGatewayStatus_NotRunning(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"missing file": "",
		"garbage":      "not-a-pid",
		"dead process": "2147483646",
		"negative pid": "-5",
		"blank":        "  ",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := dir + "/" + strings.ReplaceAll(name, " ", "_") + ".pid"
			if content != "" {
				if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got := detectGatewayStatus(func(k string) string {
				if k == "KEYLATCH_GATEWAY_PID" {
					return p
				}
				return ""
			})
			if got.Running || got.PID != 0 {
				t.Fatalf("detectGatewayStatus = %+v, want not running", got)
			}
		})
	}
}

func TestCCValidate_ReportsOverbroadScopeWarnings(t *testing.T) {
	cfgDir := ccEnv(t)
	tmpl := ccTemplate("ccscope", "https://api.example.invalid") + "overbroad_scopes:\n  - admin:all\n  - repo\n"
	ccWriteTemplate(t, cfgDir, "ccscope", tmpl)
	ccConnectNoTest(t, "ccscope", ccSecret("scope"))

	out, _, err := ccRun(t, "", "validate", "--strict")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	for _, want := range []string{"[WARN] admin:all: overbroad scope", "[WARN] repo: overbroad scope", "2 issue(s) found (0 error(s))"} {
		if !strings.Contains(out, want) {
			t.Errorf("validate output missing %q:\n%s", want, out)
		}
	}
}

func TestCCListCmd_ColumnsAndJSON(t *testing.T) {
	ccProvider(t, "cclist")
	secret := ccSecret("list")
	ccConnectNoTest(t, "cclist", secret)

	run := func(args ...string) string {
		t.Helper()
		cmd := newListCmd()
		cmd.Flags().String("namespace", "default", "")
		cmd.Flags().Bool("json", false, "")
		c, out, _ := ccCmdBuffers()
		c.AddCommand(cmd)
		c.SetArgs(append([]string{"list"}, args...))
		if err := c.Execute(); err != nil {
			t.Fatalf("list %v: %v", args, err)
		}
		ccAssertNoLeak(t, secret, out.String())
		return out.String()
	}

	table := run()
	if !strings.Contains(table, "PROVIDER") || !strings.Contains(table, "NAMESPACE") {
		t.Fatalf("missing header: %q", table)
	}
	if !strings.Contains(table, "cclist") || !strings.Contains(table, "gateway_typed") {
		t.Fatalf("missing row: %q", table)
	}

	var statuses []map[string]any
	if err := json.Unmarshal([]byte(run("--json")), &statuses); err != nil {
		t.Fatalf("json: %v", err)
	}
	if len(statuses) != 1 {
		t.Fatalf("statuses = %v", statuses)
	}

	if other := run("--namespace", "elsewhere"); strings.Contains(other, "cclist") {
		t.Fatalf("namespace filter ignored: %q", other)
	}
}

func TestCCPrintConnectActionableError(t *testing.T) {
	cases := []struct {
		name    string
		sf      registry.SecretField
		docs    string
		want    []string
		notWant []string
	}{
		{
			name: "label env and docs",
			sf:   registry.SecretField{Name: "api_key", Label: "API Key", EnvVar: "ACME_KEY"},
			docs: "https://acme.example/keys",
			want: []string{
				`Error: acme requires a "API Key" field.`,
				"keylatch connect acme\n",
				"ACME_KEY=<value> keylatch connect acme --from-env",
				`printf '%s' "$KEY" | keylatch connect acme -f api_key=@-`,
				"Get an API key at: https://acme.example/keys",
			},
		},
		{
			name:    "bare field",
			sf:      registry.SecretField{Name: "token"},
			want:    []string{`Error: acme requires a "token" field.`, "-f token=@-"},
			notWant: []string{"--from-env", "Get an API key"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, out, errb := ccCmdBuffers()
			printConnectActionableError(c, "acme", tc.sf, registry.ConnectionTemplate{DocsURL: tc.docs})
			if out.Len() != 0 {
				t.Fatalf("stdout must stay empty: %q", out.String())
			}
			for _, w := range tc.want {
				if !strings.Contains(errb.String(), w) {
					t.Errorf("missing %q in:\n%s", w, errb.String())
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(errb.String(), w) {
					t.Errorf("unexpected %q in:\n%s", w, errb.String())
				}
			}
		})
	}
}
