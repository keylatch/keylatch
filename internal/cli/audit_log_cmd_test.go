package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caLogEvents appends events to the fixture's audit log through the same
// logger the CLI uses.
func caLogEvents(t *testing.T, events ...audit.Event) {
	t.Helper()
	l, cleanup, err := openAuditLogger()
	require.NoError(t, err)
	defer cleanup()
	for _, e := range events {
		require.NoError(t, l.Log(context.Background(), e))
	}
}

func caAuditPath() string { return os.Getenv("KEYLATCH_AUDIT_PATH") }

func caSampleEvents() []audit.Event {
	return []audit.Event{
		{Action: audit.ActionWrite, Outcome: audit.OutcomeOK, Path: caPath, Backend: "file", ServiceName: "openrouter", RuntimeMode: "cli"},
		{Action: audit.ActionRead, Outcome: audit.OutcomeDenied, Path: caPath, Backend: "file", ServiceName: "openrouter", RuntimeMode: "mcp"},
		{Action: audit.ActionRead, Outcome: audit.OutcomeOK, Path: "default/ai/anthropic/api_key", Backend: "keychain", ServiceName: "anthropic", RuntimeMode: "cli"},
	}
}

func TestAuditSummaryCountsAndFilters(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)

	out, _, err := caRun(t, nil, "audit")
	require.NoError(t, err)
	assert.Contains(t, out, "total_events: 0")
	assert.NotContains(t, out, "oldest:")

	caLogEvents(t, caSampleEvents()...)

	out, _, err = caRun(t, nil, "audit", "--summary")
	require.NoError(t, err)
	assert.Contains(t, out, "total_events: 3")
	assert.Contains(t, out, "oldest: ")
	assert.Contains(t, out, "by_action:")
	assert.Contains(t, out, "  read: 2")
	assert.Contains(t, out, "  write: 1")
	assert.Contains(t, out, "by_outcome:")
	assert.Contains(t, out, "  denied: 1")

	out, _, err = caRun(t, nil, "audit", "--json", "--action", "read", "--path", caPath,
		"--service", "openrouter", "--since", time.Now().Add(-time.Hour).Format(time.RFC3339))
	require.NoError(t, err)
	var sum audit.Summary
	require.NoError(t, json.Unmarshal([]byte(out), &sum))
	assert.Equal(t, 1, sum.TotalEvents)
	assert.Equal(t, 1, sum.ByOutcome[audit.OutcomeDenied])

	_, _, err = caRun(t, nil, "audit", "--since", "yesterday")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit: parse --since")
}

func TestAuditCommandsNeedKeyring(t *testing.T) {
	caNewEnv(t)
	for _, args := range [][]string{
		{"audit"},
		{"audit", "--rotate"},
		{"audit", "--raw"},
		{"audit", "tail"},
		{"audit", "since", "1h"},
		{"audit", "prune", "--days", "3"},
	} {
		_, _, err := caRun(t, nil, args...)
		require.Error(t, err, args)
		assert.Contains(t, err.Error(), "load DEK", args)
	}
}

func TestAuditLoggerFailsWhenConfigDirIsAFile(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	blocker := filepath.Join(f.root, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	t.Setenv("KEYLATCH_CONFIG_DIR", filepath.Join(blocker, "sub"))
	_, _, err := openAuditLogger()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit: mkdir config dir")
}

func TestAuditSaltWithWrongModeIsRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("private file modes are not enforced on windows")
	}
	caNewVault(t, envelope.XChaCha20Poly1305)
	saltPath := os.Getenv("KEYLATCH_AUDIT_SALT_PATH")
	require.NoError(t, os.WriteFile(saltPath, make([]byte, 32), 0o644))
	require.NoError(t, os.Chmod(saltPath, 0o644))
	for _, args := range [][]string{{"audit"}, {"audit", "--raw"}, {"audit", "--verify-chain"}} {
		_, _, err := caRun(t, nil, args...)
		require.Error(t, err, args)
		assert.Contains(t, err.Error(), "salt", args)
	}
}

func TestAuditVerifyChainDetectsTampering(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	caLogEvents(t, caSampleEvents()...)

	out, _, err := caRun(t, nil, "audit", "--verify-chain")
	require.NoError(t, err)
	assert.Contains(t, out, "total_lines: 3")
	assert.Contains(t, out, "verified: 3")
	assert.Contains(t, out, "chain_ok: true")

	out, _, err = caRun(t, nil, "audit", "--verify-chain", "--json")
	require.NoError(t, err)
	var report audit.ChainReport
	require.NoError(t, json.Unmarshal([]byte(out), &report))
	assert.Equal(t, 3, report.Verified)

	out, _, err = caRun(t, nil, "audit", "--raw")
	require.NoError(t, err)
	assert.Contains(t, out, "verified: 3")
	assert.NotContains(t, out, "first_bad_line")

	data, err := os.ReadFile(caAuditPath())
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 3)
	require.NoError(t, os.WriteFile(caAuditPath(), []byte(strings.Join(lines[1:], "\n")+"\n"), 0o600))

	out, _, err = caRun(t, nil, "audit", "--verify-chain")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit chain integrity failure at line 1")
	assert.Contains(t, out, "first_bad_line: 1")
	assert.Contains(t, out, "reason: ")

	out, _, err = caRun(t, nil, "audit", "--raw")
	require.NoError(t, err)
	assert.Contains(t, out, "first_bad_line: 1")
}

func TestAuditVerifyChainMissingLog(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	_, _, err := caRun(t, nil, "audit", "--verify-chain")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit --verify-chain:")

	_, _, err = caRun(t, nil, "audit", "--raw")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit --raw:")
}

func TestAuditRawBlockedInLLMSession(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	caLogEvents(t, caSampleEvents()...)
	caSetLLMSession(t)
	out, _, err := caRun(t, nil, "audit", "--raw")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit --raw: blocked in LLM session")
	assert.Empty(t, out)
}

func TestAuditRotateMovesLogAside(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	caLogEvents(t, caSampleEvents()...)

	out, _, err := caRun(t, nil, "audit", "--rotate")
	require.NoError(t, err)
	assert.Contains(t, out, "audit log rotated")
	_, err = os.Stat(caAuditPath() + ".1")
	require.NoError(t, err)

	out, _, err = caRun(t, nil, "audit", "tail", "--json")
	require.NoError(t, err)
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var e audit.Event
		require.NoError(t, json.Unmarshal([]byte(line), &e))
		assert.NotEqual(t, audit.ActionWrite, e.Action, "rotated events must not remain in the live log")
	}
}

func TestAuditTailShowsLastLines(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	caLogEvents(t, caSampleEvents()...)

	out, _, err := caRun(t, nil, "audit", "tail", "-n", "2")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 3)
	assert.Contains(t, lines[0], "TIMESTAMP")
	assert.Contains(t, lines[1], "denied")
	assert.Contains(t, lines[2], "keychain")
	assert.NotContains(t, out, "write")

	out, _, err = caRun(t, nil, "audit", "tail", "--json")
	require.NoError(t, err)
	lines = strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 3)
	var e audit.Event
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &e))
	assert.Equal(t, audit.ActionWrite, e.Action)
	assert.Equal(t, caPath, e.Path)
}

func TestAuditSinceFiltersEvents(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)

	out, _, err := caRun(t, nil, "audit", "since", "1h")
	require.NoError(t, err)
	assert.Contains(t, out, "No audit events in the past 1h.")

	old := audit.Event{Timestamp: time.Now().Add(-72 * time.Hour), Action: audit.ActionList, Outcome: audit.OutcomeOK, Backend: "file"}
	caLogEvents(t, append([]audit.Event{old}, caSampleEvents()...)...)

	out, _, err = caRun(t, nil, "audit", "since", "24h")
	require.NoError(t, err)
	assert.Contains(t, out, "3 event(s) in the past 24h.")
	assert.NotContains(t, out, "list")

	out, _, err = caRun(t, nil, "audit", "since", "7d")
	require.NoError(t, err)
	assert.Contains(t, out, "4 event(s) in the past 7d.")

	out, _, err = caRun(t, nil, "audit", "since", "1h", "--json", "--outcome", "denied", "--provider", "FILE", "--agent", "mcp")
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 1)
	var e audit.Event
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &e))
	assert.Equal(t, audit.OutcomeDenied, e.Outcome)

	_, _, err = caRun(t, nil, "audit", "since", "1h", "--outcome", "maybe")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid --outcome "maybe"`)

	_, _, err = caRun(t, nil, "audit", "since", "soon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid duration")
}

func TestAuditPruneRemovesOldEntries(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	caLogEvents(t,
		audit.Event{Timestamp: time.Now().AddDate(0, 0, -40), Action: audit.ActionRead, Outcome: audit.OutcomeOK},
		audit.Event{Timestamp: time.Now().AddDate(0, 0, -10), Action: audit.ActionRead, Outcome: audit.OutcomeOK},
		audit.Event{Action: audit.ActionWrite, Outcome: audit.OutcomeOK},
	)

	out, _, err := caRun(t, nil, "audit", "prune")
	require.NoError(t, err)
	assert.Contains(t, out, "audit prune: removed 1 entries older than 30 days")

	out, _, err = caRun(t, nil, "audit", "prune")
	require.NoError(t, err)
	assert.Contains(t, out, "audit prune: nothing to prune")

	require.NoError(t, os.WriteFile(filepath.Join(f.configDir, "config.json"),
		[]byte(`{"version":1,"backend":"file","audit":{"retention_days":5}}`), 0o600))
	assert.Equal(t, 5, loadRetentionDays(filepath.Join(f.configDir, "config.json")))
	out, _, err = caRun(t, nil, "audit", "prune")
	require.NoError(t, err)
	assert.Contains(t, out, "removed 1 entries older than 5 days")

	n, err := runAuditRetentionSweep(0)
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	out, _, err = caRun(t, nil, "audit", "since", "365d")
	require.NoError(t, err)
	assert.Contains(t, out, "1 event(s)")
}
