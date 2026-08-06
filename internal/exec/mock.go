package exec

import (
	"context"
	"strings"
	"sync"
	"time"
)

// MockRunner records every Run call and looks up canned responses by a
// deterministic arg-signature key. Used in all backend tests.
// Thread-safe: concurrent Run calls are serialized via mu.
type MockRunner struct {
	mu sync.Mutex

	// Calls contains every Run invocation in order, with timestamps.
	Calls []MockCall

	// Responses maps arg-signature keys to canned responses. The key is
	// constructed by strings.Join(append([]string{name}, args...), "|").
	// If no matching key is found, Run returns ("", "", 0, nil).
	Responses map[string]MockResponse

	// SimulatedLatency adds an artificial delay to every Run call when non-zero.
	// Used by concurrency tests to stretch the unlock window.
	SimulatedLatency time.Duration
}

// MockCall records a single Run invocation.
type MockCall struct {
	Time  time.Time
	Name  string
	Args  []string
	Stdin []byte

	// Env records the extraEnv passed to RunEnv ("KEY=VALUE" strings).
	// Nil when the call came through Run (or RunEnv with no overrides).
	// Assertions on injected secrets (e.g. BW_SESSION) read this field
	// instead of Args, proving the value never crossed into argv.
	Env []string
}

// MockResponse is the canned response returned for a matching arg-signature key.
type MockResponse struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Err      error
}

// Run implements CommandRunner for MockRunner. Equivalent to
// RunEnv(ctx, name, args, stdin, nil).
func (m *MockRunner) Run(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int, error) {
	return m.RunEnv(ctx, name, args, stdin, nil)
}

// RunEnv implements CommandRunner for MockRunner.
// Records the call (including extraEnv, for injected-secret assertions),
// optionally sleeps for SimulatedLatency, then returns the registered
// response (or zeroed values if no response matches). The lookup key is
// built from name+args only — extraEnv does not affect response matching.
// Thread-safe: concurrent Run/RunEnv calls are serialized via mu.
func (m *MockRunner) RunEnv(_ context.Context, name string, args []string, stdin []byte, extraEnv []string) ([]byte, []byte, int, error) {
	m.mu.Lock()
	m.Calls = append(m.Calls, MockCall{
		Time:  time.Now(),
		Name:  name,
		Args:  args,
		Stdin: stdin,
		Env:   extraEnv,
	})

	latency := m.SimulatedLatency
	key := argSignature(name, args)
	var resp MockResponse
	if m.Responses != nil {
		resp = m.Responses[key]
	}
	m.mu.Unlock()

	if latency > 0 {
		time.Sleep(latency)
	}

	return resp.Stdout, resp.Stderr, resp.ExitCode, resp.Err
}

// argSignature builds the deterministic lookup key for a Run call.
func argSignature(name string, args []string) string {
	parts := make([]string, 0, 1+len(args))
	parts = append(parts, name)
	parts = append(parts, args...)
	return strings.Join(parts, "|")
}

// Reset clears the recorded calls (not the responses). Thread-safe.
func (m *MockRunner) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = nil
}

// CountCallsWithArg returns the number of recorded calls whose args slice
// contains the given substring anywhere in any argument. Thread-safe.
func (m *MockRunner) CountCallsWithArg(substr string) int {
	m.mu.Lock()
	calls := make([]MockCall, len(m.Calls))
	copy(calls, m.Calls)
	m.mu.Unlock()

	count := 0
	for _, c := range calls {
		for _, a := range c.Args {
			if strings.Contains(a, substr) {
				count++
				break
			}
		}
	}
	return count
}

// LastCallName returns the Name field of the most recent recorded call,
// or "" if no calls have been made. Thread-safe.
func (m *MockRunner) LastCallName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Calls) == 0 {
		return ""
	}
	return m.Calls[len(m.Calls)-1].Name
}

// LastCallArgs returns the Args of the most recent recorded call. Thread-safe.
func (m *MockRunner) LastCallArgs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Calls) == 0 {
		return nil
	}
	return m.Calls[len(m.Calls)-1].Args
}

// CallsCopy returns a snapshot of all recorded calls. Thread-safe.
func (m *MockRunner) CallsCopy() []MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]MockCall, len(m.Calls))
	copy(result, m.Calls)
	return result
}
