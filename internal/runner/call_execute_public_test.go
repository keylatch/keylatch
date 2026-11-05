package runner

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/template"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteAction_PublicEntryPostsJSONBody(t *testing.T) {
	var gotBody map[string]string
	var gotAuth, gotCT, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"1"}`))
	}))
	defer srv.Close()

	registerCallTestProvider(t, "test-mx-post", map[string]template.Action{
		"create": {Method: "post", Path: "/v1/items", Params: map[string]template.ParamSpec{
			"name":  {In: "body", Required: true},
			"label": {In: "body"},
		}},
	})

	res, err := ExecuteAction(context.Background(), srv.URL+"/", "test-mx-post", "create", map[string]string{"name": "n1", "ignored": "x"}, "cred-value")
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, res.StatusCode)
	assert.JSONEq(t, `{"id":"1"}`, string(res.Body))
	assert.NotContains(t, string(res.Body), "cred-value")
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, "Bearer cred-value", gotAuth)
	assert.Equal(t, "application/json", gotCT)
	assert.Equal(t, map[string]string{"name": "n1"}, gotBody, "only declared body params are sent")
}

func TestExecuteAction_CustomHeaderWithoutScheme(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_ = registry.Register(registry.ConnectionTemplate{
		Provider:       "test-mx-header",
		Category:       "test",
		AuthPlacement:  registry.AuthPlacement{In: "header", Name: "X-Api-Key"},
		TrustLevel:     registry.TrustLocalOnly,
		RuntimeSupport: registry.RuntimeSupport{Preferred: registry.RuntimeGatewayTyped, Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped}},
		SecretFields:   []registry.SecretField{{Name: "api_key", Required: true, Sensitive: true}},
		Actions:        map[string]template.Action{"ping": {Method: "GET", Path: "/ping"}},
	})
	res, err := executeAction(context.Background(), srv.URL, "test-mx-header", "ping", nil, "raw-key", srv.Client())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, "raw-key", got)
}

func TestExecuteAction_Errors(t *testing.T) {
	registerCallTestProvider(t, "test-mx-errors", map[string]template.Action{
		"get":    {Method: "GET", Path: "/v1/{id}/{other}", Params: map[string]template.ParamSpec{"id": {In: "path"}}},
		"opt":    {Method: "GET", Path: "/v1/{id}", Params: map[string]template.ParamSpec{"id": {In: "path", Required: false}}},
		"badurl": {Method: "GET", Path: "/v1"},
	})
	ctx := context.Background()

	_, err := executeAction(ctx, "http://127.0.0.1:1", "no-such-provider-mx", "x", nil, "c", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	_, err = executeAction(ctx, "http://127.0.0.1:1", "test-mx-errors", "get", map[string]string{"id": "1"}, "c", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unresolved placeholders")

	_, err = executeAction(ctx, "http://127.0.0.1:1", "test-mx-errors", "opt", nil, "c", nil)
	require.Error(t, err, "an optional but absent path param still leaves a placeholder")

	_, err = executeAction(ctx, "http://[::1", "test-mx-errors", "badurl", nil, "c", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "build action URL")

	closed := httptest.NewServer(http.NotFoundHandler())
	url := closed.URL
	closed.Close()
	_, err = executeAction(ctx, url, "test-mx-errors", "badurl", nil, "c", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "http request")
	assert.NotContains(t, err.Error(), "Bearer c")
}

func TestBuildActionURL_RequiredPathParamMissing(t *testing.T) {
	_, err := buildActionURL("http://h", "/x/{id}", nil, map[string]template.ParamSpec{"id": {In: "path", Required: true}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `path param "id" is required`)

	u, err := buildActionURL("http://h", "/x/{id}", map[string]string{"id": "a b/c", "q": "1"}, map[string]template.ParamSpec{
		"id": {In: "path", Required: true},
		"q":  {In: "query"},
	})
	require.NoError(t, err)
	assert.Equal(t, "http://h/x/a%20b%2Fc?q=1", u, "path params are escaped so they cannot add segments")
}
