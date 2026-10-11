package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// ccUpstream is an httptest provider API that records the Authorization
// header of each request and answers with status.
type ccUpstream struct {
	srv    *httptest.Server
	mu     sync.Mutex
	auths  []string
	paths  []string
	status int
	body   string
}

func ccNewUpstream(t *testing.T) *ccUpstream {
	t.Helper()
	u := &ccUpstream{status: http.StatusOK, body: `{"data":[{"id":"m1"}]}`}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.auths = append(u.auths, r.Header.Get("Authorization"))
		u.paths = append(u.paths, r.URL.RequestURI())
		status, body := u.status, u.body
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *ccUpstream) seen() ([]string, []string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.auths...), append([]string(nil), u.paths...)
}

// ccProvider installs a local template named name targeting a fresh upstream.
func ccProvider(t *testing.T, name string) *ccUpstream {
	t.Helper()
	cfgDir := ccEnv(t)
	up := ccNewUpstream(t)
	ccWriteTemplate(t, cfgDir, name, ccTemplate(name, up.srv.URL))
	return up
}

func ccVaultGet(t *testing.T, path string) (string, error) {
	t.Helper()
	st := newDispatchedStore(loadCLIConfig(nil), llmcontext.DefaultLookup)
	v, _, err := st.Get(context.Background(), path)
	return string(v), err
}

func ccAssertNoLeak(t *testing.T, secret string, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		if strings.Contains(o, secret) {
			t.Fatalf("secret value leaked into output: %q", o)
		}
	}
}

func TestCCConnect_StdinFieldVerifiedAndLifecycle(t *testing.T) {
	up := ccProvider(t, "ccprobe")
	secret := ccSecret("life")

	out, errOut, err := ccRun(t, secret+"\n", "connect", "ccprobe", "-f", "api_key=@-", "-f", "region=eu-west-1")
	if err != nil {
		t.Fatalf("connect: %v (stderr %q)", err, errOut)
	}
	if !strings.Contains(out, "v ccprobe — connection verified") {
		t.Fatalf("connect stdout = %q", out)
	}
	ccAssertNoLeak(t, secret, out, errOut)

	auths, paths := up.seen()
	if len(auths) != 1 || auths[0] != "Bearer "+secret {
		t.Fatalf("upstream auth headers = %q, want exactly one bearer with stored secret", auths)
	}
	if paths[0] != "/v1/models" {
		t.Fatalf("upstream path = %q", paths[0])
	}
	if got, err := ccVaultGet(t, "default/ai/ccprobe/api_key"); err != nil || got != secret {
		t.Fatalf("vault value = %q, %v", got, err)
	}

	statusOut, _, err := ccRun(t, "", "status", "--json")
	if err != nil {
		t.Fatalf("status --json: %v", err)
	}
	var st struct {
		Connections []struct {
			Connection struct {
				Provider string `json:"provider"`
			} `json:"connection"`
		} `json:"connections"`
		Gateway struct {
			Running bool `json:"running"`
		} `json:"gateway"`
		LLMSession bool `json:"llm_session"`
	}
	if err := json.Unmarshal([]byte(statusOut), &st); err != nil {
		t.Fatalf("status json: %v (%q)", err, statusOut)
	}
	if len(st.Connections) != 1 || st.Connections[0].Connection.Provider != "ccprobe" {
		t.Fatalf("status connections = %+v", st.Connections)
	}
	if st.Gateway.Running || st.LLMSession {
		t.Fatalf("status gateway/llm = %+v / %v", st.Gateway, st.LLMSession)
	}
	ccAssertNoLeak(t, secret, statusOut)

	dash, _, err := ccRun(t, "", "status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	for _, want := range []string{"backend=", "1 connections", "not running", "not detected", "ccprobe", "just now", "keylatch doctor"} {
		if !strings.Contains(dash, want) {
			t.Errorf("dashboard missing %q:\n%s", want, dash)
		}
	}

	desc, _, err := ccRun(t, "", "describe", "ccprobe")
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	for _, want := range []string{"Provider:     ccprobe", "Display Name: CC ccprobe", "Runtime:      gateway_typed", "models.list: List models", "api_key:"} {
		if !strings.Contains(desc, want) {
			t.Errorf("describe missing %q:\n%s", want, desc)
		}
	}
	ccAssertNoLeak(t, secret, desc)

	descJSON, _, err := ccRun(t, "", "describe", "ccprobe", "--json")
	if err != nil {
		t.Fatalf("describe --json: %v", err)
	}
	var dj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(descJSON), &dj); err != nil {
		t.Fatalf("describe json: %v (%q)", err, descJSON)
	}
	if _, ok := dj["masked_fields"]; !ok {
		t.Errorf("describe --json missing masked_fields: %s", descJSON)
	}
	ccAssertNoLeak(t, secret, descJSON)

	testOut, _, err := ccRun(t, "", "test", "ccprobe")
	if err != nil {
		t.Fatalf("test: %v", err)
	}
	if !strings.HasPrefix(testOut, "Status: connected") {
		t.Fatalf("test output = %q", testOut)
	}
	if auths, _ := up.seen(); len(auths) != 2 || auths[1] != "Bearer "+secret {
		t.Fatalf("test did not reuse stored credential: %q", auths)
	}

	valOut, _, err := ccRun(t, "", "validate")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if !strings.Contains(valOut, "(0 error(s))") {
		t.Fatalf("validate output = %q", valOut)
	}
	ccAssertNoLeak(t, secret, valOut)

	discOut, _, err := ccRun(t, "", "disconnect", "ccprobe")
	if err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if !strings.Contains(discOut, "v ccprobe — disconnected") {
		t.Fatalf("disconnect output = %q", discOut)
	}
	if _, err := ccVaultGet(t, "default/ai/ccprobe/api_key"); err == nil {
		t.Fatal("secret still present after disconnect")
	}
	empty, _, _ := ccRun(t, "", "status")
	if !strings.Contains(empty, "No connections yet") {
		t.Fatalf("status after disconnect = %q", empty)
	}
}

func TestCCConnect_JSONSuccess(t *testing.T) {
	up := ccProvider(t, "ccjson")
	secret := ccSecret("json")

	out, errOut, err := ccRun(t, secret, "connect", "ccjson", "--stdin-field", "api_key", "--json")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	var res struct {
		Connection map[string]any `json:"connection"`
		TestResult struct {
			Status     string `json:"status"`
			StatusCode int    `json:"status_code"`
		} `json:"test_result"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("connect --json output: %v (%q)", err, out)
	}
	if res.Connection["provider"] != "ccjson" || res.TestResult.Status != "connected" || res.TestResult.StatusCode != 200 {
		t.Fatalf("connect --json = %s", out)
	}
	ccAssertNoLeak(t, secret, out, errOut)
	if auths, _ := up.seen(); len(auths) != 1 || auths[0] != "Bearer "+secret {
		t.Fatalf("upstream auth = %q", auths)
	}
}

func TestCCConnect_NoTestSkipsUpstream(t *testing.T) {
	for _, tc := range []struct {
		name    string
		jsonOut bool
	}{{"text", false}, {"json", true}} {
		t.Run(tc.name, func(t *testing.T) {
			up := ccProvider(t, "ccskip")
			secret := ccSecret("skip")
			args := []string{"connect", "ccskip", "-f", "api_key=@-", "--no-test"}
			if tc.jsonOut {
				args = append(args, "--json")
			}
			out, errOut, err := ccRun(t, secret, args...)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			if tc.jsonOut {
				var res map[string]map[string]any
				if err := json.Unmarshal([]byte(out), &res); err != nil {
					t.Fatalf("json: %v (%q)", err, out)
				}
				if res["connection"]["provider"] != "ccskip" {
					t.Fatalf("json connection = %v", res)
				}
				if _, hasTest := res["test_result"]; hasTest {
					t.Fatalf("--no-test must not report a test result: %s", out)
				}
			} else if !strings.Contains(out, "v ccskip — stored (connection test skipped)") {
				t.Fatalf("stdout = %q", out)
			}
			ccAssertNoLeak(t, secret, out, errOut)
			if auths, _ := up.seen(); len(auths) != 0 {
				t.Fatalf("--no-test contacted upstream %d times", len(auths))
			}
			if got, _ := ccVaultGet(t, "default/ai/ccskip/api_key"); got != secret {
				t.Fatalf("stored value = %q", got)
			}
		})
	}
}

func TestCCConnect_FromEnvReadsTemplateEnvVar(t *testing.T) {
	up := ccProvider(t, "ccenv")
	secret := ccSecret("env")
	t.Setenv("CC_CCENV_KEY", secret)

	out, errOut, err := ccRun(t, "", "connect", "ccenv", "--from-env", "--non-interactive")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !strings.Contains(out, "connection verified") {
		t.Fatalf("stdout = %q", out)
	}
	ccAssertNoLeak(t, secret, out, errOut)
	if auths, _ := up.seen(); len(auths) != 1 || auths[0] != "Bearer "+secret {
		t.Fatalf("env value not injected upstream: %q", auths)
	}
}

func TestCCConnect_ProviderRefStoresURIVerbatim(t *testing.T) {
	ccProvider(t, "ccref")
	uri := "op://Private/ccref-item/credential"

	out, _, err := ccRun(t, "", "connect", "ccref", "--provider-ref", "api_key="+uri, "--no-test")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if !strings.Contains(out, "stored (connection test skipped)") {
		t.Fatalf("stdout = %q", out)
	}
	if got, err := ccVaultGet(t, "default/ai/ccref/api_key"); err != nil || got != uri {
		t.Fatalf("stored = %q, %v; want the reference URI, not a resolved value", got, err)
	}
}

func TestCCConnectCustom_PipedValue(t *testing.T) {
	ccEnv(t)
	secret := ccSecret("custom")

	cases := []struct {
		name      string
		fieldLine string
		wantField string
	}{
		{"default field", "", "api_key"},
		{"named field", "token", "token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ccScriptLines(t, "my-svc", tc.fieldLine)
			out, errOut, err := ccRun(t, secret+"\n", "connect", "custom")
			if err != nil {
				t.Fatalf("connect custom: %v (stderr %q)", err, errOut)
			}
			if !strings.Contains(out, "Connected: custom/my-svc ("+tc.wantField+" saved)") {
				t.Fatalf("stdout = %q", out)
			}
			ccAssertNoLeak(t, secret, out, errOut)
			if got, err := ccVaultGet(t, "default/custom/my-svc/"+tc.wantField); err != nil || got != secret {
				t.Fatalf("stored = %q, %v", got, err)
			}
			meta, err := ccVaultGet(t, "default/custom/my-svc/meta")
			if err != nil {
				t.Fatalf("meta missing: %v", err)
			}
			var conn struct {
				Provider string   `json:"provider"`
				Fields   []string `json:"fields"`
				Status   string   `json:"status"`
			}
			if err := json.Unmarshal([]byte(meta), &conn); err != nil {
				t.Fatalf("meta json: %v", err)
			}
			if conn.Provider != "my-svc" || conn.Status != "untested" || len(conn.Fields) != 1 || conn.Fields[0] != tc.wantField {
				t.Fatalf("meta = %+v", conn)
			}
			ccAssertNoLeak(t, secret, meta)
		})
	}
}
