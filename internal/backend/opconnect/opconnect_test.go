package opconnect_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/opconnect"
)

type opItem struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Category string    `json:"category"`
	Fields   []opField `json:"fields,omitempty"`
}

type opField struct {
	ID      string `json:"id,omitempty"`
	Label   string `json:"label,omitempty"`
	Purpose string `json:"purpose,omitempty"`
	Type    string `json:"type,omitempty"`
	Value   string `json:"value,omitempty"`
}

func newTestServer(vaultID string, items []opItem) *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			title := r.URL.Query().Get("title")
			var result []opItem
			for _, it := range items {
				if title == "" || it.Title == title {
					result = append(result, it)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(result)
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(opItem{ID: "new-id", Title: "new"})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	// Handler for individual items (GET and DELETE).
	for _, item := range items {
		it := item // capture loop variable
		mux.HandleFunc("/v1/vaults/"+vaultID+"/items/"+it.ID, func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(it)
			case http.MethodDelete:
				w.WriteHeader(http.StatusNoContent)
			default:
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
		})
	}

	return httptest.NewServer(mux)
}

func TestOPConnectGet(t *testing.T) {
	const vaultID = "vault-abc123"
	items := []opItem{
		{
			ID:    "item-001",
			Title: "myapp/api_key",
			Fields: []opField{
				{Label: "username", Value: "user"},
				{Label: "password", Purpose: "PASSWORD", Type: "CONCEALED", Value: "s3cr3t"},
			},
		},
	}

	srv := newTestServer(vaultID, items)
	defer srv.Close()

	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: srv.URL,
		Token:      "test-token",
		VaultID:    vaultID,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	val, meta, err := b.Get(context.Background(), "myapp/api_key")
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t"), val)
	assert.Equal(t, "op-connect", meta.Backend)
}

func TestOPConnectGet_NotFound(t *testing.T) {
	const vaultID = "vault-abc123"
	srv := newTestServer(vaultID, nil)
	defer srv.Close()

	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: srv.URL,
		Token:      "test-token",
		VaultID:    vaultID,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "missing/key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestOPConnectList(t *testing.T) {
	const vaultID = "vault-abc123"
	items := []opItem{
		{ID: "item-001", Title: "myapp/key1"},
		{ID: "item-002", Title: "myapp/key2"},
		{ID: "item-003", Title: "other/key"},
	}

	srv := newTestServer(vaultID, items)
	defer srv.Close()

	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: srv.URL,
		Token:      "test-token",
		VaultID:    vaultID,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)

	entries, err := b.List(context.Background(), "myapp")
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestOPConnectCapabilities(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)

	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapNetworkedFetch {
			found = true
			break
		}
	}
	assert.True(t, found, "op-connect must report CapNetworkedFetch")
}
