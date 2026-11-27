package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/paths"
)

func runAuditCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"audit"}, args...))
	err := root.Execute()
	return out.String(), err
}

func writeAuditEvents(t *testing.T, n int) {
	t.Helper()
	l, cleanup, err := OpenAuditLogger()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for range n {
		if err := l.Log(t.Context(), audit.Event{Action: audit.ActionRun, Outcome: audit.OutcomeOK, Extra: map[string]any{"connection": "c"}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHeadJSONShape(t *testing.T) {
	bootstrapForAudit(t)
	writeAuditEvents(t, 3)

	out, err := runAuditCmd(t, "head", "--json")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var shape map[string]any
	if err := json.Unmarshal([]byte(out), &shape); err != nil {
		t.Fatalf("output is not one JSON object: %q", out)
	}
	if len(shape) != 4 || shape["seq"] != float64(3) || shape["hash"] == "" || shape["key_id"] == "" {
		t.Fatalf("head = %v, want exactly {seq:3, hash, time, key_id}", shape)
	}
	if _, err := time.Parse(time.RFC3339Nano, shape["time"].(string)); err != nil {
		t.Fatalf("time %v: %v", shape["time"], err)
	}
}

func TestVerifyAnchorCommand(t *testing.T) {
	bootstrapForAudit(t)
	writeAuditEvents(t, 6)
	anchorFile := t.TempDir() + "/anchor.json"
	head, err := runAuditCmd(t, "head", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchorFile, []byte(head), 0o600); err != nil {
		t.Fatal(err)
	}

	if out, err := runAuditCmd(t, "verify", "--anchor", anchorFile); err != nil || !strings.Contains(out, "anchor_ok: true") {
		t.Fatalf("verify: %v\n%s", err, out)
	}

	data, err := os.ReadFile(paths.Audit(auditTestLookup))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	if err := os.WriteFile(paths.Audit(auditTestLookup), []byte(strings.Join(lines[:3], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runAuditCmd(t, "verify", "--anchor", anchorFile)
	if err == nil {
		t.Fatalf("a truncated log passed verify --anchor:\n%s", out)
	}
	if out, err := runAuditCmd(t, "verify"); err != nil {
		t.Fatalf("the truncated chain itself is intact: %v\n%s", err, out)
	}
}

func TestExportCommandRoundTrip(t *testing.T) {
	bootstrapForAudit(t)
	writeAuditEvents(t, 4)

	out, err := runAuditCmd(t, "export", "--format", "jsonl", "--since", time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 {
		t.Fatalf("exported %d lines, want 4:\n%s", len(lines), out)
	}
	var first audit.ExportedEvent
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil || first.Seq != 1 || first.Event.Action != audit.ActionRun {
		t.Fatalf("first line %q: %v", lines[0], err)
	}
	if out, err := runAuditCmd(t, "verify"); err != nil {
		t.Fatalf("verify after export: %v\n%s", err, out)
	}
	if _, err := runAuditCmd(t, "export", "--format", "csv"); err == nil {
		t.Fatal("csv export accepted")
	}
}
