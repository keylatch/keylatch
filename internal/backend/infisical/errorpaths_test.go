package infisical_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/infisical"
)

func openAgainst(t *testing.T, url string) *infisical.InfisicalBackend {
	t.Helper()
	b, err := infisical.Open(infisical.Options{
		BaseURL:      url,
		ClientID:     "cid",
		ClientSecret: "cs",
		WorkspaceID:  "ws",
		Environment:  "dev",
		SecretPath:   "/",
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return b
}

// TestTransportErrors points the backend at a closed port so every operation
// exercises its httpClient.Do error branch.
func TestTransportErrors(t *testing.T) {
	t.Parallel()
	// Reserve a port and close it so connections are refused.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	deadURL := srv.URL
	srv.Close()

	b := openAgainst(t, deadURL)
	ctx := context.Background()

	if _, _, err := b.Get(ctx, "X"); err == nil {
		t.Error("Get against closed port must error")
	}
	if err := b.Set(ctx, "X", []byte("v"), backend.Meta{}); err == nil {
		t.Error("Set against closed port must error")
	}
	if err := b.Delete(ctx, "X"); err == nil {
		t.Error("Delete against closed port must error")
	}
	if _, err := b.List(ctx, ""); err == nil {
		t.Error("List against closed port must error")
	}
}
