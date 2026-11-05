package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	runnerpkg "github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxGetJSON(t *testing.T, h http.Handler, method, path string) (int, map[string]interface{}) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	var body map[string]interface{}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	}
	return rec.Code, body
}

func TestStatusHandler_DemoBanner(t *testing.T) {
	t.Parallel()
	code, body := mxGetJSON(t, &api.StatusHandler{Scope: "admin", Demo: true}, http.MethodGet, "/api/status")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, true, body["ok"])
	assert.Equal(t, "admin", body["scope"])
	assert.Equal(t, true, body["demo"])
	assert.Contains(t, body["demo_banner"], "Demo mode")

	code, body = mxGetJSON(t, &api.StatusHandler{Scope: "read"}, http.MethodGet, "/api/status")
	require.Equal(t, http.StatusOK, code)
	_, hasBanner := body["demo_banner"]
	assert.False(t, hasBanner)

	code, _ = mxGetJSON(t, &api.StatusHandler{}, http.MethodPost, "/api/status")
	assert.Equal(t, http.StatusMethodNotAllowed, code)
}

func TestAuditSummaryHandler(t *testing.T) {
	t.Parallel()
	code, body := mxGetJSON(t, &api.AuditHandler{}, http.MethodGet, "/api/audit/summary")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, float64(0), body["totalEvents"])
	assert.Nil(t, body["lastEventAt"])

	code, _ = mxGetJSON(t, &api.AuditHandler{}, http.MethodDelete, "/api/audit/summary")
	assert.Equal(t, http.StatusMethodNotAllowed, code)
}

func TestAgentHandler_Routes(t *testing.T) {
	t.Parallel()
	h := &api.AgentHandler{}

	code, body := mxGetJSON(t, h, http.MethodGet, "/api/agent/snippet")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, true, body["noSecretsBadge"])
	assert.Contains(t, body["snippet"], "KEYLATCH_GATEWAY_URL")

	code, body = mxGetJSON(t, h, http.MethodPost, "/api/agent/setup")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, "configured", body["status"])
	assert.NotEmpty(t, body["timestamp"])

	code, _ = mxGetJSON(t, h, http.MethodPost, "/api/agent/snippet")
	assert.Equal(t, http.StatusMethodNotAllowed, code)
	code, _ = mxGetJSON(t, h, http.MethodGet, "/api/agent/setup")
	assert.Equal(t, http.StatusMethodNotAllowed, code)
	code, _ = mxGetJSON(t, h, http.MethodGet, "/api/agent/other")
	assert.Equal(t, http.StatusNotFound, code)
}

func TestGatewayHandler_RouteTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		mint         bool
		method, path string
		want         int
	}{
		{false, http.MethodPost, "/api/gateway/up", http.StatusNotImplemented},
		{false, http.MethodPost, "/api/gateway/down", http.StatusNotImplemented},
		{false, http.MethodGet, "/api/gateway/up", http.StatusNotFound},
		{false, http.MethodGet, "/api/gateway/tokens", http.StatusNotFound},
		{false, http.MethodPost, "/api/gateway/tokens", http.StatusForbidden},
		{true, http.MethodPost, "/api/gateway/tokens", http.StatusNotImplemented},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		(&api.GatewayHandler{AllowTokenMinting: tc.mint}).ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		assert.Equal(t, tc.want, rec.Code, "%s %s mint=%v", tc.method, tc.path, tc.mint)
		if tc.want == http.StatusNotImplemented {
			assert.Contains(t, rec.Body.String(), "not_implemented")
		}
	}

	rec := httptest.NewRecorder()
	(&api.BrokerHandler{}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/broker/dry-run", nil))
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestReceiptsHandler_LimitValidation(t *testing.T) {
	t.Parallel()
	// Capacity <= 0 falls back to the default ring size of 100.
	store := api.NewReceiptStore(0)
	for i := 0; i < 120; i++ {
		store.Push(runnerpkg.RuntimeReceipt{Provider: "p", ExitCode: i})
	}
	require.Len(t, store.Last(0), 100)
	assert.Equal(t, 20, store.Last(0)[0].ExitCode, "oldest entries must be evicted first")

	h := api.NewReceiptsHandler(store)
	for _, bad := range []string{"0", "-3", "abc"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/receipts?limit="+bad, nil))
		assert.Equal(t, http.StatusBadRequest, rec.Code, bad)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/receipts?limit=500", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Receipts []map[string]interface{} `json:"receipts"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Len(t, body.Receipts, 100, "limit is capped at 100")
}

func TestPushReceiptsHandler_NilStoreAndOversizedBody(t *testing.T) {
	t.Parallel()
	h := api.NewPushReceiptsHandler(nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/receipts", strings.NewReader(`{"provider":"x"}`)))
	assert.Equal(t, http.StatusNoContent, rec.Code)

	store := api.NewReceiptStore(2)
	big := `{"provider":"` + strings.Repeat("a", 20*1024) + `"}`
	rec = httptest.NewRecorder()
	api.NewPushReceiptsHandler(store).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/receipts", strings.NewReader(big)))
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, store.Last(0), "oversized receipt must not be stored")
}

func TestPMBrowse_AWSAndVaultParsing(t *testing.T) {
	t.Parallel()
	aws := `{"SecretList":[{"ARN":"arn:aws:secretsmanager:eu-west-1:1:secret:a","Name":"a"}]}`
	cases := []struct {
		pm, out   string
		wantItems []api.PMBrowseItem
	}{
		{"aws_sm", aws, []api.PMBrowseItem{{ID: "arn:aws:secretsmanager:eu-west-1:1:secret:a", Title: "a"}}},
		{"aws_sm", "garbage", []api.PMBrowseItem{}},
		{"hashivault", `["one","two/"]`, []api.PMBrowseItem{{ID: "one", Title: "one"}, {ID: "two/", Title: "two/"}}},
		{"hashivault", "{", []api.PMBrowseItem{}},
		{"op", "not-json", []api.PMBrowseItem{}},
	}
	for _, tc := range cases {
		h := api.NewPMBrowseHandler(newBrowseRunner([]byte(tc.out), 0))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/pm-browse?pm="+tc.pm, nil))
		require.Equal(t, http.StatusOK, rec.Code)
		var resp api.PMBrowseResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.True(t, resp.Authenticated, tc.pm)
		if len(tc.wantItems) == 0 {
			assert.Empty(t, resp.Items, tc.pm+" "+tc.out)
		} else {
			assert.Equal(t, tc.wantItems, resp.Items)
		}
	}
}

func TestPMBrowse_RunnerErrorMeansUnauthenticated(t *testing.T) {
	t.Parallel()
	failing := func(context.Context, string, []string) ([]byte, int, error) {
		return nil, 1, errors.New("boom")
	}
	hints := map[string]string{"op": "op signin", "aws_sm": "aws configure", "hashivault": "vault login"}
	for pm, hint := range hints {
		rec := httptest.NewRecorder()
		api.NewPMBrowseHandler(failing).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/pm-browse?pm="+pm, nil))
		require.Equal(t, http.StatusOK, rec.Code)
		var resp api.PMBrowseResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		assert.False(t, resp.Authenticated, pm)
		assert.Contains(t, resp.Hint, hint)
	}
}

func mxFakeBinDir(t *testing.T, scripts map[string]string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fakes need a POSIX shell")
	}
	dir := t.TempDir()
	for name, body := range scripts {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o755)) //nolint:gosec // test fake must be executable
	}
	return dir
}

func TestPMBrowse_DefaultRunnerExecutesCLI(t *testing.T) {
	dir := mxFakeBinDir(t, map[string]string{
		"op":    `echo '[{"id":"i1","title":"Item One"}]'` + "\n",
		"vault": "echo denied >&2\nexit 2\n",
	})
	t.Setenv("PATH", dir)
	h := api.NewPMBrowseHandler(nil)

	decode := func(pm string) api.PMBrowseResponse {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/pm-browse?pm="+pm, nil))
		require.Equal(t, http.StatusOK, rec.Code)
		var resp api.PMBrowseResponse
		require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
		return resp
	}

	op := decode("op")
	assert.True(t, op.Authenticated)
	assert.Equal(t, []api.PMBrowseItem{{ID: "i1", Title: "Item One"}}, op.Items)

	vault := decode("hashivault")
	assert.False(t, vault.Authenticated, "non-zero exit means not signed in")

	aws := decode("aws_sm")
	assert.False(t, aws.Authenticated, "missing binary means not signed in")
	assert.Contains(t, aws.Hint, "aws configure")
}

func TestPMDetect_DefaultDetectionUsesPATH(t *testing.T) {
	dir := mxFakeBinDir(t, map[string]string{"aws": "exit 0\n", "vault": "exit 0\n"})
	t.Setenv("PATH", dir)
	api.ResetPMCache()
	t.Cleanup(api.ResetPMCache)

	code, body := mxGetJSON(t, &api.PMDetectHandler{}, http.MethodGet, "/api/password-managers")
	require.Equal(t, http.StatusOK, code)
	assert.Equal(t, map[string]interface{}{"op": false, "aws_sm": true, "hashivault": true}, body)

	// The result is cached for the process lifetime until reset.
	t.Setenv("PATH", t.TempDir())
	_, body = mxGetJSON(t, &api.PMDetectHandler{}, http.MethodGet, "/api/password-managers")
	assert.Equal(t, true, body["aws_sm"])

	api.ResetPMCache()
	_, body = mxGetJSON(t, &api.PMDetectHandler{}, http.MethodGet, "/api/password-managers")
	assert.Equal(t, false, body["aws_sm"])
}

func TestFieldValidationError_Message(t *testing.T) {
	t.Parallel()
	ve := api.ValidateRefURI("api_key", "  ")
	require.NotNil(t, ve)
	assert.Equal(t, `field "api_key": reference URI must not be empty`, ve.Error())
}
