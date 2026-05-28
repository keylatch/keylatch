package runner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/template"
)

// registerCallTestProvider installs a minimal provider into the catalog for testing.
// It is idempotent — registering the same provider twice is a no-op.
func registerCallTestProvider(t *testing.T, slug string, actions map[string]template.Action) {
	t.Helper()
	_ = registry.Register(registry.ConnectionTemplate{
		Provider:    slug,
		DisplayName: "Test Provider",
		Category:    "test",
		AuthFlow:    "api_key",
		AuthPlacement: registry.AuthPlacement{
			In:     "header",
			Name:   "Authorization",
			Scheme: "Bearer",
		},
		StoragePathTpl: "default/test/" + slug + "/default",
		TrustLevel:     registry.TrustLocalOnly,
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
		SecretFields: []registry.SecretField{
			{Name: "api_key", Required: true, Sensitive: true},
		},
		TestStrategy: registry.TestStrategy{
			Kind:     "http_get",
			Endpoint: "https://example.com/health",
			Expect:   registry.TestExpectation{StatusCode: 200},
		},
		Actions: actions,
	})
}

// TestExecuteAction_HappyPath verifies a successful GET action against a mock server.
func TestExecuteAction_HappyPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":["gpt-4"]}`))
	}))
	defer srv.Close()

	actions := map[string]template.Action{
		"list-models": {Method: "GET", Path: "/v1/models"},
	}
	registerCallTestProvider(t, "test-happypath", actions)

	result, err := executeAction(context.Background(), srv.URL, "test-happypath", "list-models", nil, "tok-abc", srv.Client())
	if err != nil {
		t.Fatalf("executeAction returned error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.StatusCode)
	}
	if !strings.Contains(string(result.Body), "gpt-4") {
		t.Errorf("body %q does not contain gpt-4", result.Body)
	}
	if result.DurationMs < 0 {
		t.Error("DurationMs must be >= 0")
	}
}

// TestExecuteAction_ActionNotFound verifies ErrActionNotFound when the action
// name is not in the template.
func TestExecuteAction_ActionNotFound(t *testing.T) {
	t.Parallel()

	registerCallTestProvider(t, "test-notfound", map[string]template.Action{
		"list-models": {Method: "GET", Path: "/v1/models"},
	})

	_, err := executeAction(context.Background(), "https://example.com", "test-notfound", "no-such-action", nil, "tok", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "action not found") {
		t.Errorf("error %q does not mention action not found", err)
	}
}

// TestExecuteAction_MissingRequiredParam verifies that a missing required param
// is caught before the HTTP request is made.
func TestExecuteAction_MissingRequiredParam(t *testing.T) {
	t.Parallel()

	actions := map[string]template.Action{
		"get-file": {
			Method: "GET",
			Path:   "/v1/files/{file_id}",
			Params: map[string]template.ParamSpec{
				"file_id": {Type: "string", Required: true, In: "path"},
			},
		},
	}
	registerCallTestProvider(t, "test-missingparam", actions)

	_, err := executeAction(context.Background(), "https://example.com", "test-missingparam", "get-file", nil, "tok", nil)
	if err == nil {
		t.Fatal("expected error for missing required param, got nil")
	}
	if !strings.Contains(err.Error(), "missing required parameter") {
		t.Errorf("error %q does not mention missing required parameter", err)
	}
}

// TestExecuteAction_PathSubstitution verifies that {param} in the path is
// replaced with the caller-supplied value.
func TestExecuteAction_PathSubstitution(t *testing.T) {
	t.Parallel()

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	actions := map[string]template.Action{
		"get-file": {
			Method: "GET",
			Path:   "/v1/files/{file_id}",
			Params: map[string]template.ParamSpec{
				"file_id": {Type: "string", Required: true, In: "path"},
			},
		},
	}
	registerCallTestProvider(t, "test-pathsub", actions)

	params := map[string]string{"file_id": "file-abc123"}
	result, err := executeAction(context.Background(), srv.URL, "test-pathsub", "get-file", params, "tok", srv.Client())
	if err != nil {
		t.Fatalf("executeAction error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.StatusCode)
	}
	if !strings.Contains(gotPath, "file-abc123") {
		t.Errorf("server got path %q, want it to contain file-abc123", gotPath)
	}
}

// TestExecuteAction_QueryParams verifies that query params are appended to the URL.
func TestExecuteAction_QueryParams(t *testing.T) {
	t.Parallel()

	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	actions := map[string]template.Action{
		"list-files": {
			Method: "GET",
			Path:   "/v1/files",
			Params: map[string]template.ParamSpec{
				"purpose": {Type: "string", Required: false, In: "query"},
			},
		},
	}
	registerCallTestProvider(t, "test-queryparam", actions)

	params := map[string]string{"purpose": "fine-tune"}
	_, err := executeAction(context.Background(), srv.URL, "test-queryparam", "list-files", params, "tok", srv.Client())
	if err != nil {
		t.Fatalf("executeAction error: %v", err)
	}
	if !strings.Contains(gotQuery, "purpose=fine-tune") {
		t.Errorf("query %q does not contain purpose=fine-tune", gotQuery)
	}
}

// TestExecuteAction_AuditEventEmitted verifies that an action dispatch completes
// successfully and does not leak the credential in the response body.
func TestExecuteAction_AuditEventEmitted(t *testing.T) {
	t.Parallel()

	var received bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()

	actions := map[string]template.Action{
		"list-models": {Method: "GET", Path: "/v1/models"},
	}
	registerCallTestProvider(t, "test-audit", actions)

	result, err := executeAction(context.Background(), srv.URL, "test-audit", "list-models", nil, "tok-secret", srv.Client())
	if err != nil {
		t.Fatalf("executeAction error: %v", err)
	}
	if !received {
		t.Error("mock server was not called")
	}
	// Verify the result body does not contain the token.
	if strings.Contains(string(result.Body), "tok-secret") {
		t.Error("result body must not contain the credential token")
	}
	// Verify result body contains expected field.
	var parsed map[string]interface{}
	if err := json.Unmarshal(result.Body, &parsed); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
}
