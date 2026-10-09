package connections

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testAppKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func connectGitHubApp(t *testing.T, store *mockStore, keyPEM []byte, extra map[string][]byte) {
	t.Helper()
	fields := map[string][]byte{"private_key": bytes.Clone(keyPEM), "app_id": []byte("1234")}
	for k, v := range extra {
		fields[k] = v
	}
	_, err := Connect(context.Background(), "github-app", ConnectOptions{Namespace: "work", NonInteractive: true, Fields: fields}, store)
	require.NoError(t, err)
}

func TestGitHubAppConnectStoresInstallationsByOwner(t *testing.T) {
	store := newMockStore()
	connectGitHubApp(t, store, testAppKeyPEM(t), map[string][]byte{
		"installation_PatrikMichi": []byte("111"),
		"installation_keylatch":    []byte("222"),
	})

	v, ok := store.storedValue("work/code-hosting/github-app/config/installation_patrikmichi")
	require.True(t, ok, "owner suffix is lower-cased")
	assert.Equal(t, "111", string(v))
	v, ok = store.storedValue("work/code-hosting/github-app/config/installation_keylatch")
	require.True(t, ok)
	assert.Equal(t, "222", string(v))
	v, ok = store.storedValue("work/code-hosting/github-app/config/app_id")
	require.True(t, ok)
	assert.Equal(t, "1234", string(v))
	_, ok = store.storedValue("work/code-hosting/github-app/private_key")
	assert.True(t, ok)

	require.NoError(t, Delete(context.Background(), "github-app", "", "work", store))
	assert.Empty(t, store.data, "delete removes every installation field")
}

func TestGitHubAppConnectRejectsBadOwnerSuffix(t *testing.T) {
	store := newMockStore()
	_, err := Connect(context.Background(), "github-app", ConnectOptions{Namespace: "work", NonInteractive: true, Fields: map[string][]byte{
		"private_key":          testAppKeyPEM(t),
		"app_id":               []byte("1"),
		"installation_../evil": []byte("3"),
	}}, store)
	require.Error(t, err)
}

type captureTransport struct {
	reqs   []*http.Request
	bodies []string
	status int
}

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body := ""
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}
	c.reqs = append(c.reqs, r)
	c.bodies = append(c.bodies, body)
	return &http.Response{StatusCode: c.status, Body: io.NopCloser(strings.NewReader(`{"id":1}`)), Header: http.Header{}, Request: r}, nil
}

func TestGitHubAppConnectionTestNeverSendsKey(t *testing.T) {
	store := newMockStore()
	keyPEM := testAppKeyPEM(t)
	connectGitHubApp(t, store, keyPEM, nil)

	tr := &captureTransport{status: http.StatusOK}
	res, err := Test(context.Background(), "github-app", "", "work", store, &http.Client{Transport: tr})
	require.NoError(t, err)
	assert.Equal(t, TestStatusConnected, res.Status)

	require.Len(t, tr.reqs, 1)
	r := tr.reqs[0]
	assert.Equal(t, "https://api.github.com/app", r.URL.String())
	auth := r.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(auth, "Bearer "))
	assert.Len(t, strings.Split(strings.TrimPrefix(auth, "Bearer "), "."), 3, "a signed JWT, not the key")
	assert.NotContains(t, auth, "PRIVATE KEY")
	for name, vals := range r.Header {
		for _, v := range vals {
			assert.NotContains(t, v, "BEGIN", name)
		}
	}
	assert.NotContains(t, tr.bodies[0], "PRIVATE KEY")
}

func TestGitHubAppConnectionTestBadCredentials(t *testing.T) {
	store := newMockStore()
	connectGitHubApp(t, store, testAppKeyPEM(t), nil)
	res, err := Test(context.Background(), "github-app", "", "work", store, &http.Client{Transport: &captureTransport{status: http.StatusUnauthorized}})
	require.NoError(t, err)
	assert.Equal(t, TestStatusInvalid, res.Status)
}
