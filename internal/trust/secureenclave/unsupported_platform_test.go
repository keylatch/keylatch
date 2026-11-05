//go:build !darwin

package secureenclave

import (
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
)

func TestNewUnavailableOffDarwin(t *testing.T) {
	a, err := New(Options{Label: "x", PresenceMode: "biometric", Namespace: "n"})
	if a != nil {
		t.Fatalf("adapter = %v, want nil", a)
	}
	if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "only available on darwin") {
		t.Fatalf("err = %v", err)
	}
}
