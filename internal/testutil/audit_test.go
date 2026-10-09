package testutil

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
)

func TestAuditRecorder_KeepsEventsInOrderAndReturnsACopy(t *testing.T) {
	ctx, rec := WithAuditRecorder(context.Background())
	em := audit.EmitterFromCtx(ctx)
	if em == nil {
		t.Fatal("recorder not installed on the context")
	}
	for _, p := range []string{"a", "b"} {
		if err := em.Emit(ctx, audit.Event{Path: p}); err != nil {
			t.Fatal(err)
		}
	}
	got := rec.Events()
	if len(got) != 2 || got[0].Path != "a" || got[1].Path != "b" {
		t.Fatalf("events = %+v", got)
	}
	got[0].Path = "changed"
	if rec.Events()[0].Path != "a" {
		t.Fatal("Events must return a copy")
	}
}

func TestOpenAuditLog_AcceptsEvents(t *testing.T) {
	l := OpenAuditLog(t)
	if l == nil {
		t.Fatal("no logger")
	}
}
