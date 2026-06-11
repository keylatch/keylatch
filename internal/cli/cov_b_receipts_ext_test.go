package cli

// cov_b_receipts_ext_test.go — Agent B extended coverage for receipts_cmd.go.
// Tests: AppendReceipt, loadReceipts + saveSessions interaction,
// receipts show, receipts list --limit, parseSSEStream.
// Hermetic: no network, no OS keychain, no real keylatchd.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/runner"
)

// setupReceiptsDir redirects paths to a temp dir via KEYLATCH_CONFIG_DIR.
func setupReceiptsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	return dir
}

// makeReceipt returns a minimal valid runner.Receipt for testing.
func makeReceipt(actor, connection, capability string) runner.Receipt {
	return runner.Receipt{
		Timestamp:      time.Now().UTC(),
		Actor:          actor,
		Connection:     connection,
		Capability:     capability,
		PolicyDecision: "allow",
		ExitCode:       0,
		AuditAccessor:  "acc_" + actor,
	}
}

func TestAppendReceipt_CreatesFile(t *testing.T) {
	setupReceiptsDir(t)

	r := makeReceipt("claude", "openai", "completions")
	if err := AppendReceipt(r); err != nil {
		t.Fatalf("AppendReceipt: %v", err)
	}

	receipts, err := loadReceipts()
	if err != nil {
		t.Fatalf("loadReceipts: %v", err)
	}
	if len(receipts) != 1 {
		t.Errorf("expected 1 receipt, got: %d", len(receipts))
	}
	if receipts[0].Actor != "claude" {
		t.Errorf("expected actor 'claude', got: %s", receipts[0].Actor)
	}
}

func TestAppendReceipt_Accumulates(t *testing.T) {
	setupReceiptsDir(t)

	for i := 0; i < 5; i++ {
		r := makeReceipt("agent", "conn", "cap")
		if err := AppendReceipt(r); err != nil {
			t.Fatalf("AppendReceipt[%d]: %v", i, err)
		}
	}

	receipts, err := loadReceipts()
	if err != nil {
		t.Fatalf("loadReceipts: %v", err)
	}
	if len(receipts) != 5 {
		t.Errorf("expected 5 receipts, got: %d", len(receipts))
	}
}

func TestReceiptsList_WithLimit(t *testing.T) {
	setupReceiptsDir(t)

	for i := 0; i < 20; i++ {
		r := makeReceipt("agent", "conn", "cap")
		if err := AppendReceipt(r); err != nil {
			t.Fatalf("AppendReceipt[%d]: %v", i, err)
		}
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"receipts", "list", "--json", "--limit", "5"})

	if err := root.Execute(); err != nil {
		t.Fatalf("receipts list: %v", err)
	}

	var arr []runner.Receipt
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &arr); err != nil {
		t.Fatalf("JSON parse: %v — output: %s", err, out.String())
	}
	if len(arr) != 5 {
		t.Errorf("expected 5 receipts with --limit 5, got: %d", len(arr))
	}
}

func TestReceiptsList_JSON_HasSchema(t *testing.T) {
	setupReceiptsDir(t)

	r := makeReceipt("test-actor", "test-conn", "test-cap")
	if err := AppendReceipt(r); err != nil {
		t.Fatalf("AppendReceipt: %v", err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"receipts", "list", "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("receipts list: %v", err)
	}

	var arr []map[string]interface{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &arr); err != nil {
		t.Fatalf("JSON parse: %v — output: %s", err, out.String())
	}

	if len(arr) == 0 {
		t.Fatal("expected at least one receipt in output")
	}

	entry := arr[0]
	for _, field := range []string{"actor", "connection", "capability"} {
		if _, ok := entry[field]; !ok {
			t.Errorf("expected field %q in receipt JSON, got: %v", field, entry)
		}
	}
}

func TestReceiptsShow_Found(t *testing.T) {
	setupReceiptsDir(t)

	r := makeReceipt("agent-x", "conn-x", "cap-x")
	r.AuditAccessor = "acc_agent-x"
	if err := AppendReceipt(r); err != nil {
		t.Fatalf("AppendReceipt: %v", err)
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"receipts", "show", "acc_agent-x"})

	if err := root.Execute(); err != nil {
		t.Fatalf("receipts show: %v", err)
	}

	if !strings.Contains(out.String(), "agent-x") {
		t.Errorf("expected 'agent-x' in output, got: %s", out.String())
	}
}

func TestReceiptsShow_NotFound(t *testing.T) {
	setupReceiptsDir(t)

	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"receipts", "show", "nonexistent-accessor"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error for missing receipt")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' in error, got: %v", err)
	}
}

func TestReceiptsTail_NoFollow(t *testing.T) {
	setupReceiptsDir(t)

	// Append a few receipts.
	for i := 0; i < 3; i++ {
		r := makeReceipt("agent", "conn", "cap")
		if err := AppendReceipt(r); err != nil {
			t.Fatalf("AppendReceipt[%d]: %v", i, err)
		}
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"receipts", "tail"})

	if err := root.Execute(); err != nil {
		t.Fatalf("receipts tail: %v", err)
	}

	// Should have 3 JSON lines.
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines from tail, got %d: %s", len(lines), out.String())
	}
}

func TestReceiptsTail_NoFollow_LimitsTo10(t *testing.T) {
	setupReceiptsDir(t)

	for i := 0; i < 15; i++ {
		r := makeReceipt("agent", "conn", "cap")
		if err := AppendReceipt(r); err != nil {
			t.Fatalf("AppendReceipt[%d]: %v", i, err)
		}
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"receipts", "tail"})

	if err := root.Execute(); err != nil {
		t.Fatalf("receipts tail: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 10 {
		t.Errorf("expected 10 lines (tail limit), got: %d", len(lines))
	}
}

// TestParseSSEStream tests the SSE parser directly with an io.Reader.
func TestParseSSEStream_ReceiptEvents(t *testing.T) {
	// Construct a minimal SSE stream.
	sseData := "event: receipt\ndata: {\"actor\":\"test\"}\n\nevent: other\ndata: ignore\n\nevent: receipt\ndata: {\"actor\":\"test2\"}\n\n"

	var out bytes.Buffer
	if err := parseSSEStream(strings.NewReader(sseData), &out); err != nil {
		t.Fatalf("parseSSEStream: %v", err)
	}

	result := out.String()
	if !strings.Contains(result, `"actor":"test"`) {
		t.Errorf("expected first receipt in output, got: %s", result)
	}
	if !strings.Contains(result, `"actor":"test2"`) {
		t.Errorf("expected second receipt in output, got: %s", result)
	}
	// Non-receipt events should be skipped.
	if strings.Contains(result, "ignore") {
		t.Errorf("non-receipt event data should not appear, got: %s", result)
	}
}

func TestParseSSEStream_EmptyInput(t *testing.T) {
	var out bytes.Buffer
	if err := parseSSEStream(strings.NewReader(""), &out); err != nil {
		t.Fatalf("parseSSEStream empty: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected empty output for empty input, got: %s", out.String())
	}
}

func TestParseSSEStream_EventTypeResetOnBlankLine(t *testing.T) {
	// After a blank line, eventType resets. Data without a preceding event: line
	// should NOT be printed.
	sseData := "event: receipt\ndata: first\n\ndata: orphan\n\n"

	var out bytes.Buffer
	if err := parseSSEStream(strings.NewReader(sseData), &out); err != nil {
		t.Fatalf("parseSSEStream: %v", err)
	}

	result := out.String()
	if !strings.Contains(result, "first") {
		t.Errorf("expected 'first' receipt data in output, got: %s", result)
	}
	if strings.Contains(result, "orphan") {
		t.Errorf("orphan data without event type should not appear, got: %s", result)
	}
}
