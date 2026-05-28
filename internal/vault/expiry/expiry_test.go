package expiry

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/vault/meta"
)

// resetWarnedPaths clears the deduplication set between subtests.
// Only compiled in test binaries (file ends in _test.go).
func resetWarnedPaths() {
	warnedPaths.Range(func(key, _ any) bool {
		warnedPaths.Delete(key)
		return true
	})
}

func metaWithExpiry(t time.Time) meta.Meta {
	return meta.Meta{
		Path:      "default/ai/openrouter/api_key",
		ExpiresAt: &t,
	}
}

func metaNoExpiry() meta.Meta {
	return meta.Meta{Path: "default/ai/openrouter/api_key"}
}

// -----------------------------------------------------------------------
// IsExpired
// -----------------------------------------------------------------------

func TestIsExpired(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	justPast := now.Add(-time.Nanosecond)

	cases := []struct {
		name string
		m    meta.Meta
		want bool
	}{
		{"nil ExpiresAt", metaNoExpiry(), false},
		{"past date", metaWithExpiry(past), true},
		{"future date", metaWithExpiry(future), false},
		{"just past now", metaWithExpiry(justPast), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsExpired(tc.m, now)
			if got != tc.want {
				t.Errorf("want %v, got %v", tc.want, got)
			}
		})
	}
}

// -----------------------------------------------------------------------
// DaysRemaining
// -----------------------------------------------------------------------

func TestDaysRemaining(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name string
		m    meta.Meta
		want int
	}{
		{"nil ExpiresAt", metaNoExpiry(), 1<<31 - 1},
		{"expired 2 days ago", metaWithExpiry(now.Add(-48 * time.Hour)), -2},
		{"expires in 30 days", metaWithExpiry(now.Add(30 * 24 * time.Hour)), 30},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DaysRemaining(tc.m, now)
			if got != tc.want {
				t.Errorf("want %d, got %d", tc.want, got)
			}
		})
	}
}

// -----------------------------------------------------------------------
// Status
// -----------------------------------------------------------------------

func TestStatus(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name     string
		m        meta.Meta
		warnDays int
		want     string
	}{
		{"ok — no expiry", metaNoExpiry(), 30, "ok"},
		{"ok — far future", metaWithExpiry(now.Add(90 * 24 * time.Hour)), 30, "ok"},
		{"warn — at boundary", metaWithExpiry(now.Add(30 * 24 * time.Hour)), 30, "warn"},
		{"warn — within boundary", metaWithExpiry(now.Add(15 * 24 * time.Hour)), 30, "warn"},
		{"expired", metaWithExpiry(now.Add(-time.Hour)), 30, "expired"},
		{"expired takes priority over warn", metaWithExpiry(now.Add(-time.Nanosecond)), 30, "expired"},
		{"zero warnDays uses default", metaWithExpiry(now.Add(15 * 24 * time.Hour)), 0, "warn"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Status(tc.m, now, tc.warnDays)
			if got != tc.want {
				t.Errorf("want %q, got %q", tc.want, got)
			}
		})
	}
}

// -----------------------------------------------------------------------
// WarnOnce — stderr capture
// -----------------------------------------------------------------------

func TestWarnOnce_EmitsOnce(t *testing.T) {
	resetWarnedPaths()

	now := time.Now()
	past := now.Add(-time.Hour)
	m := metaWithExpiry(past)
	// Use a unique path to avoid cross-test interference.
	m.Path = "default/ai/warnonce-emits-once/api_key"

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	for i := 0; i < 5; i++ {
		WarnOnce(t.Context(), m)
	}

	w.Close()
	os.Stderr = origStderr

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, readErr := r.Read(tmp)
		buf.Write(tmp[:n])
		if readErr != nil {
			break
		}
	}
	r.Close()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	nonEmpty := 0
	for _, l := range lines {
		if l != "" {
			nonEmpty++
		}
	}

	if nonEmpty != 1 {
		t.Errorf("expected exactly 1 warning line, got %d: %q", nonEmpty, buf.String())
	}
}

func TestWarnOnce_NonExpiredEmitsNothing(t *testing.T) {
	resetWarnedPaths()

	now := time.Now()
	future := now.Add(24 * time.Hour)
	m := metaWithExpiry(future)
	m.Path = "default/ai/warnonce-non-expired/api_key"

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	WarnOnce(t.Context(), m)

	w.Close()
	os.Stderr = origStderr

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, readErr := r.Read(tmp)
		buf.Write(tmp[:n])
		if readErr != nil {
			break
		}
	}
	r.Close()

	if buf.Len() > 0 {
		t.Errorf("expected no output, got: %q", buf.String())
	}
}

func TestWarnOnce_ConcurrentCallsEmitOnce(t *testing.T) {
	resetWarnedPaths()

	now := time.Now()
	past := now.Add(-time.Hour)

	// Use a unique path so this test doesn't interfere with others.
	m := meta.Meta{
		Path:      "default/ai/concurrent/api_key",
		ExpiresAt: &past,
	}

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			WarnOnce(t.Context(), m)
		}()
	}
	wg.Wait()

	w.Close()
	os.Stderr = origStderr

	var buf strings.Builder
	tmp := make([]byte, 4096)
	for {
		n, readErr := r.Read(tmp)
		buf.Write(tmp[:n])
		if readErr != nil {
			break
		}
	}
	r.Close()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	nonEmpty := 0
	for _, l := range lines {
		if l != "" {
			nonEmpty++
		}
	}

	if nonEmpty != 1 {
		t.Errorf("expected exactly 1 warning line from %d goroutines, got %d: %q",
			goroutines, nonEmpty, buf.String())
	}
}
