package expiry

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/vault/meta"
)

// warnedPaths is a process-scoped deduplication set; key type string (canonical path).
var warnedPaths sync.Map

// WarnOnce emits exactly one warning per (path, process) to stderr when the
// secret is expired. Subsequent calls for the same path are no-ops.
//
// Security invariant: warning format is "[keylatch] warn: <path> expired on <date>".
// The warning MUST NOT include any value bytes. MUST NOT write to stdout.
//
// ctx is accepted for future cancellation but not currently used.
func WarnOnce(ctx context.Context, m meta.Meta) {
	if !IsExpired(m, time.Now()) {
		return
	}

	// LoadOrStore returns (existing, loaded). If loaded is true, already warned.
	if _, loaded := warnedPaths.LoadOrStore(m.Path, struct{}{}); loaded {
		return
	}

	slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})).
		Warn("secret expired", "path", m.Path, "expires_at", m.ExpiresAt.Format(time.RFC3339))
}
