package cli

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/spf13/cobra"
)

// ccReceiptSink is a fake keylatchd UI endpoint collecting pushed receipts.
func ccReceiptSink(t *testing.T) chan runner.RuntimeReceipt {
	t.Helper()
	got := make(chan runner.RuntimeReceipt, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/receipts" || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		var rr runner.RuntimeReceipt
		if err := json.NewDecoder(r.Body).Decode(&rr); err == nil {
			got <- rr
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("KEYLATCH_UI_ADDR", srv.Listener.Addr().String())
	return got
}

func ccConnectNoTest(t *testing.T, provider, secret string) {
	t.Helper()
	if _, errOut, err := ccRun(t, secret, "connect", provider, "-f", "api_key=@-", "--no-test"); err != nil {
		t.Fatalf("connect %s: %v (%s)", provider, err, errOut)
	}
}

func TestCCCall_TextRedactsAndPushesReceipt(t *testing.T) {
	up := ccProvider(t, "cccall")
	secret := ccSecret("call")
	ccConnectNoTest(t, "cccall", secret)
	sink := ccReceiptSink(t)

	leaked := "s" + "k-" + strings.Repeat("Ab1Cd2", 6)
	up.body = `{"data":[{"id":"m1"}],"echo":"` + leaked + `"}`

	out, errOut, err := ccRun(t, "", "call", "cccall", "list-models", "--no-daemon-start", "--runtime", "gateway_typed")
	if err != nil {
		t.Fatalf("call: %v (%s)", err, errOut)
	}
	if !strings.Contains(out, `"id":"m1"`) {
		t.Fatalf("stdout missing body: %q", out)
	}
	if strings.Contains(out, leaked) || !strings.Contains(out, "[REDACTED:") {
		t.Fatalf("response body not redacted: %q", out)
	}
	ccAssertNoLeak(t, secret, out, errOut)
	if auths, paths := up.seen(); len(auths) != 1 || auths[0] != "Bearer "+secret || paths[0] != "/v1/models" {
		t.Fatalf("upstream saw auth=%q paths=%q", auths, paths)
	}

	select {
	case rr := <-sink:
		if rr.Provider != "cccall" || rr.Capability != "list-models" || rr.PolicyDecision != "approved" ||
			rr.Runtime != "gateway_typed" || rr.CredentialShape != "provider_root" || rr.TTL != time.Hour {
			t.Fatalf("receipt = %+v", rr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no receipt pushed to UI endpoint")
	}
}

func TestCCCall_JSONLines(t *testing.T) {
	cases := []struct {
		name           string
		body           string
		includeHeaders bool
		wantBody       string
	}{
		{"json body", `{"data":[]}`, false, `{"data":[]}`},
		{"plain body is quoted", `not json`, false, `"not json"`},
		{"headers without authorization", `{"ok":true}`, true, `{"ok":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := ccProvider(t, "ccjsonl")
			secret := ccSecret("jl")
			ccConnectNoTest(t, "ccjsonl", secret)
			up.body = tc.body

			args := []string{"call", "ccjsonl", "list-models", "--no-daemon-start", "--json"}
			if tc.includeHeaders {
				args = append(args, "--include-headers")
			}
			out, errOut, err := ccRun(t, "", args...)
			if err != nil {
				t.Fatalf("call: %v (%s)", err, errOut)
			}
			var line struct {
				StatusCode int                 `json:"status_code"`
				Body       json.RawMessage     `json:"body"`
				Headers    map[string][]string `json:"headers"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &line); err != nil {
				t.Fatalf("json line: %v (%q)", err, out)
			}
			if line.StatusCode != 200 || string(line.Body) != tc.wantBody {
				t.Fatalf("line = %d %s", line.StatusCode, line.Body)
			}
			if tc.includeHeaders {
				if line.Headers["Content-Type"] == nil {
					t.Fatalf("headers missing Content-Type: %v", line.Headers)
				}
			} else if line.Headers != nil {
				t.Fatalf("headers present without --include-headers: %v", line.Headers)
			}
			ccAssertNoLeak(t, secret, out, errOut)
		})
	}
}

func TestCCCall_ListNoActions(t *testing.T) {
	cfgDir := ccEnv(t)
	tmpl := ccTemplate("ccbare", "https://api.example.invalid")
	tmpl = strings.Replace(tmpl, "actions:\n  list-models:\n    method: GET\n    path: /v1/models\n", "", 1)
	ccWriteTemplate(t, cfgDir, "ccbare", tmpl)

	out, _, err := ccRun(t, "", "call", "ccbare", "--list")
	if err != nil {
		t.Fatalf("call --list: %v", err)
	}
	if !strings.Contains(out, `Provider "ccbare" has no actions defined.`) {
		t.Fatalf("stdout = %q", out)
	}
	out, _, err = ccRun(t, "", "call", "ccbare", "--list", "--json")
	if err != nil {
		t.Fatalf("call --list --json: %v", err)
	}
	if strings.TrimSpace(out) != `{"actions":[],"provider":"ccbare"}` {
		t.Fatalf("json = %q", out)
	}
}

func TestCCCall_ListUnknownProviderAndArgs(t *testing.T) {
	ccEnv(t)
	_, errOut, err := ccRun(t, "", "call", "ccnope", "--list")
	if err == nil || !strings.Contains(err.Error(), `provider "ccnope" not found`) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(errOut, "KL-3002") {
		t.Fatalf("stderr missing error code: %q", errOut)
	}

	if _, _, err := ccRun(t, "", "call", "--list"); err == nil || !strings.Contains(err.Error(), "requires a connection name") {
		t.Fatalf("--list without connection: %v", err)
	}
	if _, _, err := ccRun(t, "", "call", "openai"); err == nil || !strings.Contains(err.Error(), "requires exactly 2 arguments") {
		t.Fatalf("one arg without --list: %v", err)
	}
}

func ccCmdBuffers() (*cobra.Command, *bytes.Buffer, *bytes.Buffer) {
	c := &cobra.Command{}
	var out, errb bytes.Buffer
	c.SetOut(&out)
	c.SetErr(&errb)
	return c, &out, &errb
}

func TestCCPrintStructuredError(t *testing.T) {
	c, out, errb := ccCmdBuffers()
	printStructuredError(c, true, "action_not_found", "no such action", "try --list")
	var parsed map[string]map[string]string
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("json: %v (%q)", err, out.String())
	}
	if parsed["error"]["code"] != "action_not_found" || parsed["error"]["message"] != "no such action" || parsed["error"]["hint"] != "try --list" {
		t.Fatalf("parsed = %v", parsed)
	}
	if errb.Len() != 0 {
		t.Fatalf("json mode wrote to stderr: %q", errb.String())
	}

	c, out, errb = ccCmdBuffers()
	printStructuredError(c, false, "x", "boom", "do this")
	if errb.String() != "Error: boom\n  do this\n" || out.Len() != 0 {
		t.Fatalf("human = %q / %q", errb.String(), out.String())
	}

	c, _, errb = ccCmdBuffers()
	printStructuredError(c, false, "x", "boom", "")
	if errb.String() != "Error: boom\n" {
		t.Fatalf("human without hint = %q", errb.String())
	}
}

func TestCCPrintCallResultJSON_StripsAuthorization(t *testing.T) {
	c, out, _ := ccCmdBuffers()
	h := http.Header{}
	h.Set("Authorization", "Bearer "+ccSecret("hdr"))
	h.Set("X-Request-Id", "r1")
	printCallResultJSON(c, 201, 7, []byte(`[1,2]`), h, true)
	if strings.Contains(out.String(), ccSecret("hdr")) || strings.Contains(strings.ToLower(out.String()), "authorization") {
		t.Fatalf("authorization header leaked: %q", out.String())
	}
	var line struct {
		StatusCode int                 `json:"status_code"`
		DurationMs int64               `json:"duration_ms"`
		Body       json.RawMessage     `json:"body"`
		Headers    map[string][]string `json:"headers"`
	}
	if err := json.Unmarshal(out.Bytes(), &line); err != nil {
		t.Fatalf("json: %v", err)
	}
	if line.StatusCode != 201 || line.DurationMs != 7 || string(line.Body) != "[1,2]" || line.Headers["X-Request-Id"][0] != "r1" {
		t.Fatalf("line = %+v", line)
	}
}

func TestCCEmitCallMetaLog_OnlyAllowlistedFields(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	emitCallMetaLog("chat", &registry.GatewayAction{
		MaskingProfile: "strict",
		AllowedFields:  []string{"id"},
		RequiredScopes: []string{"read"},
		LLMSessionDeny: true,
	}, registry.ExchangeStaticGatewayOnly)

	var rec struct {
		Msg      string `json:"msg"`
		Metadata string `json:"metadata"`
	}
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log json: %v (%q)", err, buf.String())
	}
	if rec.Msg != "keylatch call metadata" {
		t.Fatalf("msg = %q", rec.Msg)
	}
	var meta map[string]any
	if err := json.Unmarshal([]byte(rec.Metadata), &meta); err != nil {
		t.Fatalf("metadata json: %v", err)
	}
	for k := range meta {
		if !callMetaAllowedFields[k] {
			t.Errorf("non-allowlisted key %q logged", k)
		}
	}
	if meta["action"] != "chat" || meta["exchange_strategy"] != "static_gateway_only" || meta["masking_profile"] != "strict" || meta["llm_session_deny"] != true {
		t.Fatalf("metadata = %v", meta)
	}
}

func TestCCPushReceiptToUI_BestEffort(t *testing.T) {
	sink := ccReceiptSink(t)
	sinkAddr := os.Getenv("KEYLATCH_UI_ADDR")

	// A port outside 1..65535 is rejected before any request is built.
	t.Setenv("KEYLATCH_UI_ADDR", "127.0.0.1:70000")
	pushReceiptToUI(t.Context(), runner.RuntimeReceipt{Provider: "malformed"})

	// A valid address with nothing listening is a silent no-op.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := closed.Addr().String()
	_ = closed.Close()
	t.Setenv("KEYLATCH_UI_ADDR", addr)
	pushReceiptToUI(t.Context(), runner.RuntimeReceipt{Provider: "unreachable"})

	t.Setenv("KEYLATCH_UI_ADDR", sinkAddr)
	pushReceiptToUI(t.Context(), runner.RuntimeReceipt{Provider: "pushed", Capability: "c"})
	select {
	case rr := <-sink:
		if rr.Provider != "pushed" || rr.Capability != "c" {
			t.Fatalf("receipt = %+v; only the valid address may receive a push", rr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("receipt not delivered")
	}
}
