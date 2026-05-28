package canary_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/canary"
)

// spyTB is a testing.TB spy that captures Errorf calls without failing the
// real test. Only the methods used by AssertNoLeak need to be implemented.
type spyTB struct {
	testing.TB
	errors []string
}

func (s *spyTB) Helper() {}

func (s *spyTB) Errorf(format string, args ...any) {
	s.errors = append(s.errors, fmt.Sprintf(format, args...))
}

// TestAssertNoLeak_NoLeak verifies that AssertNoLeak passes when the sentinel
// is absent from all channels.
func TestAssertNoLeak_NoLeak(t *testing.T) {
	spy := &spyTB{}
	canary.AssertNoLeak(spy,
		[]string{canary.Phase0Sentinel},
		canary.Stdout([]byte("safe stdout")),
		canary.Stderr([]byte("safe stderr")),
	)
	if len(spy.errors) != 0 {
		t.Errorf("expected no errors, got %d: %v", len(spy.errors), spy.errors)
	}
}

// TestAssertNoLeak_StdoutLeak verifies that a sentinel present in stdout
// triggers exactly one Errorf call.
func TestAssertNoLeak_StdoutLeak(t *testing.T) {
	sentinel := canary.Phase0Sentinel
	spy := &spyTB{}
	canary.AssertNoLeak(spy,
		[]string{sentinel},
		canary.Stdout([]byte("output contains "+sentinel+" here")),
	)
	if len(spy.errors) != 1 {
		t.Errorf("expected 1 error, got %d: %v", len(spy.errors), spy.errors)
	}
}

// TestAssertNoLeak_JSONResponseLeak verifies that a sentinel embedded in a
// JSON-serialised struct is detected.
func TestAssertNoLeak_JSONResponseLeak(t *testing.T) {
	sentinel := canary.Phase1Sentinel
	type payload struct {
		Secret string `json:"secret"`
	}
	spy := &spyTB{}
	canary.AssertNoLeak(spy,
		[]string{sentinel},
		canary.JSONResponse(payload{Secret: sentinel}),
	)
	if len(spy.errors) != 1 {
		t.Errorf("expected 1 error from JSONResponse, got %d: %v", len(spy.errors), spy.errors)
	}
}

// TestAssertNoLeak_FileLeak verifies that a sentinel written to a temp file
// is detected via the File channel.
func TestAssertNoLeak_FileLeak(t *testing.T) {
	sentinel := canary.Phase2Sentinel
	dir := t.TempDir()
	path := filepath.Join(dir, "output.txt")
	if err := os.WriteFile(path, []byte("leaking: "+sentinel), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	spy := &spyTB{}
	canary.AssertNoLeak(spy,
		[]string{sentinel},
		canary.File(path),
	)
	if len(spy.errors) != 1 {
		t.Errorf("expected 1 error from File channel, got %d: %v", len(spy.errors), spy.errors)
	}
}

// TestAssertNoLeak_MultipleSentinelsMultipleChannels verifies that all leaks
// across multiple sentinels and channels are reported in a single pass.
func TestAssertNoLeak_MultipleSentinelsMultipleChannels(t *testing.T) {
	s0 := canary.Phase0Sentinel
	s1 := canary.Phase1Sentinel

	spy := &spyTB{}
	canary.AssertNoLeak(spy,
		[]string{s0, s1},
		canary.Stdout([]byte("stdout has "+s0)),
		canary.Stderr([]byte("stderr has "+s1)),
	)
	// Expect two errors: one per (sentinel, channel) match.
	if len(spy.errors) != 2 {
		t.Errorf("expected 2 errors, got %d: %v", len(spy.errors), spy.errors)
	}
}

// TestAssertNoLeak_ExcerptHidesRawSentinel verifies that the excerpt context
// portion of the error message does not contain the raw sentinel — it uses
// "<<SENTINEL>>" instead. The error message preamble may still name the sentinel
// for identification; only the context excerpt is checked here.
func TestAssertNoLeak_ExcerptHidesRawSentinel(t *testing.T) {
	sentinel := canary.Phase3Sentinel
	spy := &spyTB{}
	canary.AssertNoLeak(spy,
		[]string{sentinel},
		canary.Stdout([]byte("prefix_"+sentinel+"_suffix")),
	)
	if len(spy.errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(spy.errors))
	}
	msg := spy.errors[0]

	// Extract the excerpt portion after "excerpt: ".
	const excerptLabel = "excerpt: "
	excerptIdx := strings.Index(msg, excerptLabel)
	if excerptIdx == -1 {
		t.Fatalf("error message missing 'excerpt:' section: %s", msg)
	}
	excerpt := msg[excerptIdx+len(excerptLabel):]

	if strings.Contains(excerpt, sentinel) {
		t.Errorf("excerpt must not contain raw sentinel, but got: %s", excerpt)
	}
	if !strings.Contains(excerpt, "<<SENTINEL>>") {
		t.Errorf("excerpt must contain <<SENTINEL>>, but got: %s", excerpt)
	}
}

func TestFileChannel_MissingFileNoFalsePositive(t *testing.T) {
	ch := canary.File("/nonexistent/path/that/does/not/exist/canary_test")
	if ch.Bytes() != nil {
		t.Errorf("File channel for missing path: Bytes() = %v, want nil", ch.Bytes())
	}
}
