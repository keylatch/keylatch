// Package canary provides sentinel-based secret leak detection for tests.
// It is intentionally stdlib-only: no keylatch production imports allowed.
package canary

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Sentinel constants. Each phase gets a distinct sentinel so leaks can be
// attributed to the originating phase.
const (
	Phase0Sentinel = "KEYLATCH_CANARY_PHASE0_0xDEADBEEF"
	Phase1Sentinel = "KEYLATCH_CANARY_PHASE1_0xDEADBEEF"
	Phase2Sentinel = "KEYLATCH_CANARY_PHASE2_0xDEADBEEF"
	Phase3Sentinel = "KEYLATCH_CANARY_PHASE3_0xDEADBEEF"
	Phase4Sentinel = "KEYLATCH_CANARY_PHASE4_0xDEADBEEF"
	Phase5Sentinel = "KEYLATCH_CANARY_PHASE5_0xDEADBEEF"
	// Phase 6 and Phase 7 do not have value-bearing paths requiring canary
	// protection (Phase 6 is test infrastructure; Phase 7 is release tooling).
	Phase8Sentinel         = "KEYLATCH_CANARY_PHASE8_0xDEADBEEF"
	Phase9Sentinel         = "KEYLATCH_CANARY_PHASE9_0xDEADBEEF"
	Phase10Sentinel        = "KEYLATCH_CANARY_PHASE10_0xDEADBEEF"
	Phase11Sentinel        = "KEYLATCH_CANARY_PHASE11_0xDEADBEEF"
	Phase12Sentinel        = "KEYLATCH_CANARY_PHASE12_0xDEADBEEF"
	Phase13Sentinel        = "KEYLATCH_CANARY_PHASE13_0xDEADBEEF"
	Phase14DesktopSentinel = "KEYLATCH_CANARY_PHASE14_DESKTOP_0xDEADBEEF"
)

// RegisteredSentinels returns every canary sentinel managed by this package.
func RegisteredSentinels() []string {
	return []string{
		Phase0Sentinel,
		Phase1Sentinel,
		Phase2Sentinel,
		Phase3Sentinel,
		Phase4Sentinel,
		Phase5Sentinel,
		Phase8Sentinel,
		Phase9Sentinel,
		Phase10Sentinel,
		Phase11Sentinel,
		Phase12Sentinel,
		Phase13Sentinel,
		Phase14DesktopSentinel,
	}
}

// Channel is an observable output surface that may contain leaked sentinels.
type Channel interface {
	// Name returns a human-readable description (e.g. "stdout", "stderr", "file:/tmp/out").
	Name() string
	// Bytes returns the raw content of the channel to scan.
	Bytes() []byte
}

// stdoutChannel wraps captured stdout bytes.
type stdoutChannel struct{ b []byte }

func (c *stdoutChannel) Name() string  { return "stdout" }
func (c *stdoutChannel) Bytes() []byte { return c.b }

// Stdout returns a Channel backed by the provided bytes representing stdout.
func Stdout(b []byte) Channel { return &stdoutChannel{b: b} }

// stderrChannel wraps captured stderr bytes.
type stderrChannel struct{ b []byte }

func (c *stderrChannel) Name() string  { return "stderr" }
func (c *stderrChannel) Bytes() []byte { return c.b }

// Stderr returns a Channel backed by the provided bytes representing stderr.
func Stderr(b []byte) Channel { return &stderrChannel{b: b} }

// fileChannel reads from a file path lazily when Bytes() is called.
type fileChannel struct{ path string }

func (c *fileChannel) Name() string { return "file:" + c.path }
func (c *fileChannel) Bytes() []byte {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return nil
	}
	return b
}

// File returns a Channel that reads lazily from path.
// If the file cannot be read, Bytes() returns nil (empty).
func File(path string) Channel { return &fileChannel{path: path} }

// jsonResponseChannel marshals a Go value to JSON when Bytes() is called.
type jsonResponseChannel struct{ v any }

func (c *jsonResponseChannel) Name() string { return "json_response" }
func (c *jsonResponseChannel) Bytes() []byte {
	b, err := json.Marshal(c.v)
	if err != nil {
		return nil
	}
	return b
}

// JSONResponse returns a Channel that marshals v via json.Marshal.
// If marshalling fails, Bytes() returns nil (empty).
func JSONResponse(v any) Channel { return &jsonResponseChannel{v: v} }

// LeakReport records a detected sentinel leak with context.
type LeakReport struct {
	// Sentinel is the raw sentinel string that was found.
	Sentinel string
	// Channel is the Name() of the channel where the leak was found.
	Channel string
	// Excerpt is up to 40 characters of context around the match;
	// the raw sentinel is replaced with "<<SENTINEL>>" in the excerpt.
	Excerpt string
}

// AssertNoLeak checks every (sentinel, channel) pair for leaks.
// For each match it builds a LeakReport and calls t.Errorf (not t.FailNow)
// so that all leaks are reported in a single test run.
func AssertNoLeak(t testing.TB, sentinels []string, channels ...Channel) {
	t.Helper()
	for _, ch := range channels {
		content := ch.Bytes()
		if len(content) == 0 {
			continue
		}
		for _, sentinel := range sentinels {
			if !bytes.Contains(content, []byte(sentinel)) {
				continue
			}
			report := buildReport(sentinel, ch.Name(), content)
			t.Errorf("canary leak detected: sentinel %q found in %s — excerpt: %s",
				report.Sentinel, report.Channel, report.Excerpt)
		}
	}
}

// buildReport constructs a LeakReport for a detected leak.
// excerpt is ≤40 chars of context around the first match, with the sentinel
// replaced by "<<SENTINEL>>" so the raw value does not appear in test output.
func buildReport(sentinel, channelName string, content []byte) LeakReport {
	idx := bytes.Index(content, []byte(sentinel))
	// Compute a window of ≤40 bytes around the match (20 before, 20 after).
	const window = 20
	start := idx - window
	if start < 0 {
		start = 0
	}
	end := idx + len(sentinel) + window
	if end > len(content) {
		end = len(content)
	}
	raw := string(content[start:end])
	excerpt := strings.ReplaceAll(raw, sentinel, "<<SENTINEL>>")

	return LeakReport{
		Sentinel: sentinel,
		Channel:  channelName,
		Excerpt:  excerpt,
	}
}
