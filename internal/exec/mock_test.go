package exec_test

import (
	"context"
	"sync"
	"testing"
	"time"

	kexec "github.com/keylatch/keylatch/internal/exec"
)

// TestMockRunner_ResponseRegisteredAndRecorded verifies that a canned response
// registered in Responses is returned by Run and that the call is recorded.
func TestMockRunner_ResponseRegisteredAndRecorded(t *testing.T) {
	m := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/usr/bin/security|find-generic-password|-w": {
				Stdout:   []byte("secret-value\n"),
				ExitCode: 0,
			},
		},
	}

	ctx := context.Background()
	stdout, _, code, err := m.Run(ctx, "/usr/bin/security", []string{"find-generic-password", "-w"}, nil)
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	if code != 0 {
		t.Errorf("exit code: got %d, want 0", code)
	}
	if string(stdout) != "secret-value\n" {
		t.Errorf("stdout: got %q, want %q", stdout, "secret-value\n")
	}
	calls := m.CallsCopy()
	if len(calls) != 1 {
		t.Fatalf("Calls: got %d, want 1", len(calls))
	}
	if calls[0].Name != "/usr/bin/security" {
		t.Errorf("Call.Name: got %q, want %q", calls[0].Name, "/usr/bin/security")
	}
}

// TestMockRunner_MultipleResponses verifies that the correct response is
// selected when multiple keys are registered.
func TestMockRunner_MultipleResponses(t *testing.T) {
	m := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/echo|hello": {Stdout: []byte("hello\n")},
			"/bin/echo|world": {Stdout: []byte("world\n")},
		},
	}
	ctx := context.Background()

	tests := []struct {
		args []string
		want string
	}{
		{[]string{"hello"}, "hello\n"},
		{[]string{"world"}, "world\n"},
	}
	for _, tc := range tests {
		stdout, _, _, err := m.Run(ctx, "/bin/echo", tc.args, nil)
		if err != nil {
			t.Errorf("Run(%v): %v", tc.args, err)
			continue
		}
		if string(stdout) != tc.want {
			t.Errorf("Run(%v): got %q, want %q", tc.args, stdout, tc.want)
		}
	}
}

// TestMockRunner_FallbackOnNoMatch verifies that Run returns zeroed values when
// no matching key exists in Responses.
func TestMockRunner_FallbackOnNoMatch(t *testing.T) {
	m := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/echo|hello": {Stdout: []byte("hello\n")},
		},
	}
	ctx := context.Background()
	stdout, stderr, code, err := m.Run(ctx, "/bin/echo", []string{"no-match"}, nil)
	if err != nil || code != 0 || stdout != nil || stderr != nil {
		t.Errorf("fallback: got (%v, %v, %d, %v), want (nil, nil, 0, nil)", stdout, stderr, code, err)
	}
}

// TestMockRunner_NilResponsesReturnsZero verifies that a MockRunner with nil
// Responses does not panic and returns zeroed values.
func TestMockRunner_NilResponsesReturnsZero(t *testing.T) {
	m := &kexec.MockRunner{} // Responses is nil
	ctx := context.Background()
	stdout, stderr, code, err := m.Run(ctx, "/bin/echo", nil, nil)
	if err != nil || code != 0 || stdout != nil || stderr != nil {
		t.Errorf("nil responses: got (%v, %v, %d, %v), want (nil, nil, 0, nil)", stdout, stderr, code, err)
	}
}

// TestMockRunner_CallOrderPreserved verifies that multiple Run calls are
// recorded in the order they were made.
func TestMockRunner_CallOrderPreserved(t *testing.T) {
	m := &kexec.MockRunner{}
	ctx := context.Background()

	names := []string{"/bin/first", "/bin/second", "/bin/third"}
	for _, name := range names {
		_, _, _, _ = m.Run(ctx, name, nil, nil)
	}

	calls := m.CallsCopy()
	if len(calls) != len(names) {
		t.Fatalf("Calls: got %d, want %d", len(calls), len(names))
	}
	for i, want := range names {
		if calls[i].Name != want {
			t.Errorf("Calls[%d].Name: got %q, want %q", i, calls[i].Name, want)
		}
	}
}

// TestMockRunner_SimulatedLatency verifies that when SimulatedLatency is set,
// each Run call takes at least that long.
func TestMockRunner_SimulatedLatency(t *testing.T) {
	latency := 20 * time.Millisecond
	m := &kexec.MockRunner{
		SimulatedLatency: latency,
	}
	ctx := context.Background()

	start := time.Now()
	_, _, _, _ = m.Run(ctx, "/bin/true", nil, nil)
	elapsed := time.Since(start)

	if elapsed < latency {
		t.Errorf("elapsed %v < SimulatedLatency %v", elapsed, latency)
	}
}

// TestMockRunner_ConcurrentRunsNoRace verifies that concurrent Run calls from
// multiple goroutines do not trigger the race detector.
func TestMockRunner_ConcurrentRunsNoRace(t *testing.T) {
	m := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/echo|ping": {Stdout: []byte("pong\n")},
		},
	}
	ctx := context.Background()

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _, _, _ = m.Run(ctx, "/bin/echo", []string{"ping"}, nil)
		}()
	}
	wg.Wait()

	got := len(m.CallsCopy())
	if got != goroutines {
		t.Errorf("Calls: got %d, want %d", got, goroutines)
	}
}
