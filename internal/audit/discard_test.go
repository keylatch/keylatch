package audit_test

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
)

func TestDiscardIsReadyAndDropsEvents(t *testing.T) {
	var e audit.Emitter = audit.Discard{}
	if err := audit.Ready(e); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	if err := e.Emit(context.Background(), audit.Event{Action: audit.ActionRun}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
}
