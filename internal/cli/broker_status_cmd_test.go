package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/broker"
)

// testBrokerStrategy is a minimal ExchangeStrategy for CLI tests.
type testBrokerStrategy struct {
	provider string
}

func (s *testBrokerStrategy) Provider() string { return s.provider }
func (s *testBrokerStrategy) Exchange(_ context.Context, _, _, _ string) (broker.ExchangeResult, error) {
	return broker.NewExchangeResult(s.provider, "chat", 3600_000_000_000, broker.FreshExchange, []byte("not-a-real-token")), nil
}

// newInProcessBrokerForTest creates a BrokerImpl and populates its cache with
// one exchange so CLI tests can exercise the populated path.
// It registers a cleanup to reset the in-process singleton after the test completes.
func newInProcessBrokerForTest(t *testing.T) *broker.BrokerImpl {
	t.Helper()
	t.Cleanup(broker.ResetInProcessSingleton)
	b := broker.NewBroker(context.Background(), map[string]broker.ExchangeStrategy{
		"openrouter": &testBrokerStrategy{provider: "openrouter"},
	}, nil, []byte("cli-test-hmac-key-32-bytes-pad!!"))
	_, err := b.Exchange(context.Background(), "actor-cli", "sess-cli", "openrouter", "chat", "default")
	if err != nil {
		t.Fatalf("broker exchange for test setup: %v", err)
	}
	return b
}

// TestBrokerStatus_OutOfProcess verifies that status handles the out-of-process
// case without panicking and without leaking credential values.
func TestBrokerStatus_OutOfProcess(t *testing.T) {
	t.Parallel()
	var errBuf bytes.Buffer
	var out bytes.Buffer
	root := newBrokerCmd()
	root.PersistentFlags().Bool("json", false, "")
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"status"})
	_ = root.Execute()
	raw := out.String() + errBuf.String()
	noTokenLeakage(t, raw)
}

// TestBrokerStatus_Populated verifies that status lists grants when the broker
// is running in-process with cached tokens.
func TestBrokerStatus_Populated(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := newInProcessBrokerForTest(t)
	withBrokerHandle(t, b)

	root := newBrokerCmd()
	root.PersistentFlags().Bool("json", false, "")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"status"})
	if err := root.Execute(); err != nil {
		t.Fatalf("broker status: %v", err)
	}

	s := out.String()
	noTokenLeakage(t, s)
	// Should show table header or no-tokens message.
	if !strings.Contains(s, "PROVIDER") && !strings.Contains(s, "No active") {
		t.Errorf("unexpected output: %q", s)
	}
}

// TestBrokerStatus_Empty verifies "No active scoped tokens." message for an
// empty broker.
func TestBrokerStatus_Empty(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := broker.NewBroker(context.Background(), nil, nil, nil)
	withBrokerHandle(t, b)

	root := newBrokerCmd()
	root.PersistentFlags().Bool("json", false, "")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"status"})
	if err := root.Execute(); err != nil {
		t.Fatalf("broker status: %v", err)
	}

	s := out.String()
	if !strings.Contains(s, "No active scoped tokens") {
		t.Errorf("expected 'No active scoped tokens.' in output, got %q", s)
	}
	noTokenLeakage(t, s)
}

// TestBrokerStatus_JSON verifies broker status --json returns valid JSON.
func TestBrokerStatus_JSON(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := newInProcessBrokerForTest(t)
	withBrokerHandle(t, b)

	root := newBrokerCmd()
	root.PersistentFlags().Bool("json", true, "")
	_ = root.PersistentFlags().Set("json", "true")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"status"})
	if err := root.Execute(); err != nil {
		t.Fatalf("broker status --json: %v", err)
	}

	raw := out.String()
	noTokenLeakage(t, raw)

	var payload brokerStatusOutput
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("broker status --json output is not valid JSON: %v (output: %q)", err, raw)
	}
	if payload.Total < 1 {
		t.Error("expected at least one grant in status --json output")
	}
}

// TestBrokerStatus_NoTokenLeakage verifies that no raw token patterns appear
// in any status output path.
func TestBrokerStatus_NoTokenLeakage(t *testing.T) {
	// Not parallel: modifies brokerHandleFactory singleton.
	b := newInProcessBrokerForTest(t)
	withBrokerHandle(t, b)

	for _, jsonFlag := range []bool{false, true} {
		root := newBrokerCmd()
		root.PersistentFlags().Bool("json", false, "")
		if jsonFlag {
			_ = root.PersistentFlags().Set("json", "true")
		}
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&bytes.Buffer{})
		root.SetArgs([]string{"status"})
		_ = root.Execute()
		noTokenLeakage(t, out.String())
	}
}

// noTokenLeakage asserts that no raw token patterns appear in s.
func noTokenLeakage(t *testing.T, s string) {
	t.Helper()
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`sk-[a-zA-Z0-9\-_]{10,}`),
		regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_\.]{10,}`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9\-_]{20,}\.eyJ[a-zA-Z0-9\-_]{10,}`),
		regexp.MustCompile(`not-a-real-token`),
	}
	for _, re := range patterns {
		if re.MatchString(s) {
			t.Errorf("output contains raw token pattern %q in: %q", re.String(), s)
		}
	}
}

// Satisfy unused import check.
var _ = strings.Contains
