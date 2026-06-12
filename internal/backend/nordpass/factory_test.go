package nordpass

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// TestFactoryAndIdentity covers the factory and the trivial identity methods
// of the discovery-gated stub.
func TestFactoryAndIdentity(t *testing.T) {
	t.Parallel()
	b, err := nordpassFactory(context.Background(), backend.BackendConfig{})
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	np, ok := b.(*NordPassBackend)
	if !ok {
		t.Fatalf("factory returned %T", b)
	}
	if np.Name() != "nordpass" {
		t.Errorf("Name = %q", np.Name())
	}
	if np.Capabilities() != nil {
		t.Errorf("Capabilities = %v, want nil for stub", np.Capabilities())
	}
	if np.ID() != "nordpass:stub" {
		t.Errorf("ID = %q", np.ID())
	}
	if err := np.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
