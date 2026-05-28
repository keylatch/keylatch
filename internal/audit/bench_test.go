package audit_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
)

// BenchmarkAuditLogContended runs b.N goroutines calling Log() under contention.
// Target: < 50ms total overhead.
// Track regressions: benchstat old.txt new.txt
func BenchmarkAuditLogContended(b *testing.B) {
	dir := b.TempDir()
	auditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(auditDir, 0o700); err != nil {
		b.Fatalf("MkdirAll: %v", err)
	}

	salt := make([]byte, 32)
	dek := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
		dek[i] = byte(i + 50)
	}

	l, err := audit.Open(filepath.Join(auditDir, "bench.log"), salt, dek)
	if err != nil {
		b.Fatalf("audit.Open: %v", err)
	}
	b.Cleanup(func() { l.Close() })

	ctx := context.Background()
	event := audit.Event{
		Action:  audit.ActionRead,
		Outcome: audit.OutcomeOK,
		Path:    "bench/secret",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = l.Log(ctx, event)
		}
	})
	b.StopTimer()

	// ReportMetric approximation: wall-clock/N underestimates per-op cost under
	// GOMAXPROCS > 1. Use `benchstat old.txt new.txt` for regression tracking.
	b.ReportMetric(float64(b.Elapsed().Milliseconds())/float64(b.N), "ms/op")
}
