package connections

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxRecorded captures what the provider test endpoint received.
type mxRecorded struct {
	mu     sync.Mutex
	method string
	path   string
	header http.Header
	query  url.Values
}

// mxTestServer starts an httptest server answering with status/body and
// returns a client whose transport rewrites every request to that server, so
// registry endpoints never reach the network.
func mxTestServer(t *testing.T, status int, body string) (*http.Client, *mxRecorded) {
	t.Helper()
	rec := &mxRecorded{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.header = r.Header.Clone()
		rec.query = r.URL.Query()
		rec.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	target, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return &http.Client{Transport: mxRewrite{target: target, base: srv.Client().Transport}}, rec
}

type mxRewrite struct {
	target *url.URL
	base   http.RoundTripper
}

func (m mxRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Scheme = m.target.Scheme
	r2.URL.Host = m.target.Host
	return m.base.RoundTrip(r2)
}

func mxConnect(t *testing.T, store Store, provider string) {
	t.Helper()
	tmpl, err := registry.Get(provider)
	require.NoError(t, err)
	fields := map[string][]byte{}
	for _, sf := range tmpl.SecretFields {
		fields[sf.Name] = []byte("value-for-" + sf.Name)
	}
	_, err = Connect(context.Background(), provider, ConnectOptions{NonInteractive: true, Fields: fields}, store)
	require.NoError(t, err)
}

func TestTest_HeaderBearerAuthAndMarkers(t *testing.T) {
	store := newMockStore()
	mxConnect(t, store, "openrouter")
	client, rec := mxTestServer(t, http.StatusOK, `{"data":[]}`)

	res, err := Test(context.Background(), "openrouter", "", "", store, client)
	require.NoError(t, err)
	assert.Equal(t, TestStatusConnected, res.Status)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Equal(t, []string{"data"}, res.Markers)
	assert.Equal(t, "openrouter", res.Provider)
	assert.Equal(t, "default/openrouter/default", res.Connection)
	assert.NotEmpty(t, res.Duration)

	assert.Equal(t, http.MethodGet, rec.method)
	assert.Equal(t, "/api/v1/models", rec.path)
	assert.Equal(t, "Bearer value-for-api_key", rec.header.Get("Authorization"))

	// A successful test stamps LastTested on the stored metadata.
	conn, err := loadConnection(context.Background(), "default", "openrouter", "default", store)
	require.NoError(t, err)
	require.NotNil(t, conn.LastTested)
}

func TestTest_HeaderWithoutScheme(t *testing.T) {
	store := newMockStore()
	mxConnect(t, store, "anthropic")
	client, rec := mxTestServer(t, http.StatusUnauthorized, `{}`)

	res, err := Test(context.Background(), "anthropic", "default", "default", store, client)
	require.NoError(t, err)
	assert.Equal(t, TestStatusInvalid, res.Status)
	assert.Equal(t, "value-for-api_key", rec.header.Get("x-api-key"))
	assert.Empty(t, res.Markers, "markers only come from a matching body")
}

func TestTest_QueryAuthPlacement(t *testing.T) {
	store := newMockStore()
	mxConnect(t, store, "google-ai")
	client, rec := mxTestServer(t, http.StatusForbidden, `{"models":[]}`)

	res, err := Test(context.Background(), "google-ai", "", "", store, client)
	require.NoError(t, err)
	assert.Equal(t, TestStatusInsufficientScope, res.Status)
	assert.Equal(t, "value-for-api_key", rec.query.Get("key"))
	assert.Equal(t, []string{"models"}, res.Markers)
}

func TestTest_HTTPPostStrategy(t *testing.T) {
	store := newMockStore()
	mxConnect(t, store, "dropbox")
	client, rec := mxTestServer(t, http.StatusTooManyRequests, ``)

	res, err := Test(context.Background(), "dropbox", "", "", store, client)
	require.NoError(t, err)
	assert.Equal(t, TestStatusRateLimited, res.Status)
	assert.Equal(t, http.MethodPost, rec.method)
}

func TestTest_UnreachableEndpointIsNetworkError(t *testing.T) {
	store := newMockStore()
	mxConnect(t, store, "openrouter")
	failing := &http.Client{Transport: mxFailTransport{}}

	res, err := Test(context.Background(), "openrouter", "", "", store, failing)
	require.NoError(t, err)
	assert.Equal(t, TestStatusNetworkError, res.Status)
	assert.Zero(t, res.StatusCode)

	// No LastTested stamp for a failed probe.
	conn, err := loadConnection(context.Background(), "default", "openrouter", "default", store)
	require.NoError(t, err)
	assert.Nil(t, conn.LastTested)
}

type mxFailTransport struct{}

func (mxFailTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("dial refused: upstream detail must not leak")
}

func TestTest_TemplatedEndpointFailsBeforeNetwork(t *testing.T) {
	store := newMockStore()
	mxConnect(t, store, "auth0")
	// The unresolved {domain} placeholder makes the URL invalid; the probe
	// must fail closed without contacting anything.
	res, err := Test(context.Background(), "auth0", "", "", store, &http.Client{Transport: mxFailTransport{}})
	require.NoError(t, err)
	assert.Equal(t, TestStatusNetworkError, res.Status)
}

func TestTest_MissingConnection(t *testing.T) {
	res, err := Test(context.Background(), "openrouter", "", "", newMockStore(), nil)
	require.NoError(t, err)
	assert.Equal(t, TestStatusMissing, res.Status)
	assert.Equal(t, "openrouter", res.Provider)
}

func TestTest_StoreAndRegistryErrors(t *testing.T) {
	_, err := Test(context.Background(), "openrouter", "", "", errStore{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load connection")

	// Metadata stored for a provider that is not in the registry.
	store := newMockStore()
	require.NoError(t, store.Set(context.Background(), "default/ai/ghost-provider/meta", []byte(`{"provider":"ghost-provider"}`), backend.Meta{}))
	_, err = Test(context.Background(), "ghost-provider", "", "", store, nil)
	assert.ErrorIs(t, err, ErrProviderNotFound)
}

func TestExecuteTestStrategy_UnknownKind(t *testing.T) {
	res, err := executeTestStrategy(context.Background(), registry.TestStrategy{Kind: "carrier_pigeon"}, "openrouter", "default", "default", nil, newMockStore(), http.DefaultClient)
	require.NoError(t, err)
	assert.Equal(t, TestStatusNetworkError, res.Status)
}

func TestRunHTTPStrategy_TokenShapedMarkerDropped(t *testing.T) {
	long := strings.Repeat("Q", 40)
	client, _ := mxTestServer(t, http.StatusOK, "prefix "+long+" ok")
	strategy := registry.TestStrategy{
		Kind:     "http_get",
		Endpoint: "https://example.invalid/probe",
		Expect:   registry.TestExpectation{Markers: []string{"ok", long, "absent"}},
	}
	res, err := runHTTPStrategy(context.Background(), http.MethodGet, strategy, "openrouter", "default", "default", newMockStore(), client)
	require.NoError(t, err)
	assert.Equal(t, []string{"ok"}, res.Markers)
}

func TestMapHTTPStatusToEnum_Remaining(t *testing.T) {
	assert.Equal(t, TestStatusMissing, mapHTTPStatusToEnum(404))
	assert.Equal(t, TestStatusNetworkError, mapHTTPStatusToEnum(302))
}

func TestStripTokenShapedSubstrings_KeepsShortWords(t *testing.T) {
	assert.Equal(t, "hello world", stripTokenShapedSubstrings("hello world"))
	assert.Equal(t, "key=****", stripTokenShapedSubstrings("key="+strings.Repeat("z", 33)))
}

func TestUpdateLastTested_Errors(t *testing.T) {
	ctx := context.Background()
	assert.ErrorIs(t, updateLastTested(ctx, "default", "openrouter", "default", newMockStore()), backend.ErrNotFound)

	store := newMockStore()
	require.NoError(t, store.Set(ctx, "default/ai/openrouter/meta", []byte("{corrupt"), backend.Meta{}))
	assert.Error(t, updateLastTested(ctx, "default", "openrouter", "default", store))
}
