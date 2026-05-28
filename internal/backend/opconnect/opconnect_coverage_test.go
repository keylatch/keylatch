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
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

func openOPConnect(t *testing.T, srv *httptest.Server, vaultID string) *opconnect.OPConnectBackend {
	t.Helper()
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: srv.URL,
		Token:      "test-token",
		VaultID:    vaultID,
		HTTPClient: srv.Client(),
	})
	require.NoError(t, err)
	return b
}

func TestOPName(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)
	assert.Equal(t, "op-connect", b.Name())
}

func TestOPID(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://myserver:8080",
		Token:      "tok",
		VaultID:    "vault-123",
	})
	require.NoError(t, err)
	id := b.ID()
	assert.Contains(t, id, "op-connect")
	assert.Contains(t, id, "vault-123")
}

func TestOPClose(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)
	assert.NoError(t, b.Close())
}

func TestOPSet(t *testing.T) {
	const vaultID = "vault-set-test"
	var created []opItem

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]opItem{})
		case http.MethodPost:
			var item opItem
			_ = json.NewDecoder(r.Body).Decode(&item)
			item.ID = "new-id"
			created = append(created, item)
			w.WriteHeader(http.StatusCreated)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(item)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := openOPConnect(t, srv, vaultID)
	err := b.Set(context.Background(), "myapp/api_key", []byte("secret-value"), backend.Meta{})
	require.NoError(t, err)
	assert.Len(t, created, 1, "Set should have created one item")
}

func TestOPSet_Error(t *testing.T) {
	const vaultID = "vault-err-test"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode([]opItem{})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := openOPConnect(t, srv, vaultID)
	err := b.Set(context.Background(), "key", []byte("val"), backend.Meta{})
	require.Error(t, err)
}

func TestOPDelete_Success(t *testing.T) {
	const vaultID = "vault-del-test"
	items := []opItem{
		{ID: "del-item-001", Title: "myapp/del_key"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, r *http.Request) {
		title := r.URL.Query().Get("title")
		var result []opItem
		for _, it := range items {
			if title == "" || it.Title == title {
				result = append(result, it)
			}
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items/del-item-001", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := openOPConnect(t, srv, vaultID)
	err := b.Delete(context.Background(), "myapp/del_key")
	require.NoError(t, err)
}

func TestOPDelete_NotFound(t *testing.T) {
	const vaultID = "vault-notfound-test"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]opItem{}) // empty list
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := openOPConnect(t, srv, vaultID)
	err := b.Delete(context.Background(), "missing/key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestOPDelete_ItemNotFoundHTTP(t *testing.T) {
	const vaultID = "vault-http404-test"
	items := []opItem{{ID: "item-404", Title: "key"}}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, r *http.Request) {
		title := r.URL.Query().Get("title")
		var result []opItem
		for _, it := range items {
			if title == "" || it.Title == title {
				result = append(result, it)
			}
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items/item-404", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := openOPConnect(t, srv, vaultID)
	err := b.Delete(context.Background(), "key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestOPGet_LabelFallback(t *testing.T) {
	// Test the extractOPValue fallback: no PASSWORD purpose field,
	// but a field labelled with the path.
	const vaultID = "vault-label-test"
	items := []opItem{
		{
			ID:    "label-item-001",
			Title: "myapp/label_key",
			Fields: []opField{
				{Label: "myapp/label_key", Value: "label-secret"},
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, r *http.Request) {
		title := r.URL.Query().Get("title")
		var result []opItem
		for _, it := range items {
			if title == "" || it.Title == title {
				result = append(result, it)
			}
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	for _, item := range items {
		it := item
		mux.HandleFunc("/v1/vaults/"+vaultID+"/items/"+it.ID, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(it)
			}
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := openOPConnect(t, srv, vaultID)
	val, _, err := b.Get(context.Background(), "myapp/label_key")
	require.NoError(t, err)
	assert.Equal(t, []byte("label-secret"), val)
}

func TestOPGet_FirstFieldFallback(t *testing.T) {
	// Test the extractOPValue fallback: first field value when no purpose or label match.
	const vaultID = "vault-firstfield-test"
	items := []opItem{
		{
			ID:    "ff-item-001",
			Title: "myapp/ff_key",
			Fields: []opField{
				{Label: "something_else", Value: "first-secret"},
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, r *http.Request) {
		title := r.URL.Query().Get("title")
		var result []opItem
		for _, it := range items {
			if title == "" || it.Title == title {
				result = append(result, it)
			}
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	for _, item := range items {
		it := item
		mux.HandleFunc("/v1/vaults/"+vaultID+"/items/"+it.ID, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(it)
			}
		})
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := openOPConnect(t, srv, vaultID)
	val, _, err := b.Get(context.Background(), "myapp/ff_key")
	require.NoError(t, err)
	assert.Equal(t, []byte("first-secret"), val)
}

func TestOPGet_NoFields(t *testing.T) {
	// Test: item found but has no fields → ErrNotFound.
	const vaultID = "vault-nofields-test"
	items := []opItem{
		{ID: "nf-item-001", Title: "myapp/nf_key"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items", func(w http.ResponseWriter, r *http.Request) {
		title := r.URL.Query().Get("title")
		var result []opItem
		for _, it := range items {
			if title == "" || it.Title == title {
				result = append(result, it)
			}
		}
		_ = json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("/v1/vaults/"+vaultID+"/items/nf-item-001", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(opItem{ID: "nf-item-001", Title: "myapp/nf_key"})
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	b := openOPConnect(t, srv, vaultID)
	_, _, err := b.Get(context.Background(), "myapp/nf_key")
	require.Error(t, err)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestOPOpen_MissingConnectURL(t *testing.T) {
	_, err := opconnect.Open(opconnect.Options{
		Token:   "tok",
		VaultID: "vid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connect_url")
}

func TestOPOpen_MissingToken(t *testing.T) {
	_, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost",
		VaultID:    "vid",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "token")
}

func TestOPOpen_MissingVaultID(t *testing.T) {
	_, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost",
		Token:      "tok",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault_id")
}

func TestOPGetMeta_NotSupported(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)
	_, err = b.GetMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestOPSetMeta_NotSupported(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)
	err = b.SetMeta(context.Background(), "any/path", vmeta.Meta{})
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestOPListMeta_NotSupported(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)
	_, err = b.ListMeta(context.Background(), "any/path")
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestOPGetVersioned_NotSupported(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)
	_, err = b.GetVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestOPSetVersioned_NotSupported(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)
	err = b.SetVersioned(context.Background(), "any/path", 1, []byte("val"))
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestOPDeleteVersioned_NotSupported(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)
	err = b.DeleteVersioned(context.Background(), "any/path", 1)
	assert.ErrorIs(t, err, backend.ErrNotSupported)
}

func TestOPCapabilities_HasCapList(t *testing.T) {
	b, err := opconnect.Open(opconnect.Options{
		ConnectURL: "http://localhost:8080",
		Token:      "tok",
		VaultID:    "vid",
	})
	require.NoError(t, err)
	caps := b.Capabilities()
	found := false
	for _, c := range caps {
		if c == backend.CapList {
			found = true
			break
		}
	}
	assert.True(t, found, "op-connect must report CapList")
}
