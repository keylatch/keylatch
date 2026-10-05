package testutil

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
)

// AuditRecorder is an audit.Emitter that keeps events in memory, for tests
// that drive paths which refuse to run unaudited.
type AuditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

// Emit records e.
func (r *AuditRecorder) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

// Events returns a copy of the recorded events.
func (r *AuditRecorder) Events() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

// WithAuditRecorder returns ctx carrying a fresh AuditRecorder.
func WithAuditRecorder(ctx context.Context) (context.Context, *AuditRecorder) {
	r := &AuditRecorder{}
	return audit.WithEmitter(ctx, r), r
}

// OpenAuditLog opens a real audit log in a temporary directory; it is
// closed when the test ends.
func OpenAuditLog(t testing.TB) *audit.Logger {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	l, err := audit.Open(filepath.Join(dir, "audit.log"), make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}
