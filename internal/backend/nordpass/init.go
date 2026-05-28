package nordpass

import (
	"context"
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/backend"
)

func init() {
	if os.Getenv("KEYLATCH_EXPERIMENTAL") != "1" {
		return
	}
	if err := backend.Default.Register("nordpass", nordpassFactory); err != nil {
		backend.AppendRegistrationError(fmt.Errorf("backend/nordpass: %w", err))
	}
}

func nordpassFactory(_ context.Context, _ backend.BackendConfig) (backend.Backend, error) {
	return &NordPassBackend{}, nil
}
