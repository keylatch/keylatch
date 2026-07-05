// Package cli — coverage agent A: pure/utility unit tests (a–l files).
// File: cov_a_pure_unit_test.go
// Scope: unexported functions accessed via internal package tests.
//
//	Covers: guard_runtime.go, audit_tail_cmd.go, approve_cmd.go,
//	        cmd_backup.go, cmd_call.go, cmd_status.go, grant_cmd.go,
//	        json_output.go, config_cmd.go, errors.go, check_expiry_cmd.go,
//	        init_integration_cmd.go, bootstrap_cmd.go.
package cli

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/registry"
)

// ---------------------------------------------------------------------------
// guard_runtime.go — suggestMode, levenshtein
// ---------------------------------------------------------------------------

func TestLevenshtein_Basics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"kitten", "sitting", 3},
		{"gateway_typed", "gateway_tyqed", 1},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%s/%s", tc.a, tc.b), func(t *testing.T) {
			t.Parallel()
			got := levenshtein(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("levenshtein(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestSuggestMode_CloseMatch(t *testing.T) {
	t.Parallel()
	// "gateway_type" is 1 char away from "gateway_typed" — should match.
	got := suggestMode("gateway_type")
	if got == "" {
		t.Error("expected a suggestion for 'gateway_type', got empty string")
	}
}

func TestSuggestMode_ExactMatch(t *testing.T) {
	t.Parallel()
	got := suggestMode("gateway_typed")
	if got != "gateway_typed" {
		t.Errorf("suggestMode(exact) = %q, want 'gateway_typed'", got)
	}
}

func TestSuggestMode_NoMatch(t *testing.T) {
	t.Parallel()
	got := suggestMode("xyzzy_totally_unknown_mode_that_does_not_exist")
	if got != "" {
		t.Errorf("expected no suggestion for gibberish, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// audit_tail_cmd.go — parseDuration, parsePositiveInt, prettyEvent, loadRetentionDays
// ---------------------------------------------------------------------------

func TestParseDuration_ValidDays(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  time.Duration
	}{
		{"1d", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := parseDuration(tc.input)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("parseDuration(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseDuration_ValidGoSyntax(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  time.Duration
	}{
		{"1h", time.Hour},
		{"30m", 30 * time.Minute},
		{"2h30m", 2*time.Hour + 30*time.Minute},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := parseDuration(tc.input)
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("parseDuration(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseDuration_Invalid(t *testing.T) {
	t.Parallel()
	cases := []string{
		"0d", "-1d", "abcd", "0h", "-1h", "", "xd",
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%q", tc), func(t *testing.T) {
			t.Parallel()
			_, err := parseDuration(tc)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tc)
			}
		})
	}
}

func TestParsePositiveInt_Valid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  int64
	}{
		{"1", 1},
		{"7", 7},
		{"30", 30},
		{"100", 100},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := parsePositiveInt(tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("parsePositiveInt(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

func TestParsePositiveInt_Invalid(t *testing.T) {
	t.Parallel()
	cases := []string{"", "0", "-1", "abc", "1a", "1.5"}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%q", tc), func(t *testing.T) {
			t.Parallel()
			_, err := parsePositiveInt(tc)
			if err == nil {
				t.Errorf("expected error for %q, got nil", tc)
			}
		})
	}
}

func TestPrettyEvent_Basic(t *testing.T) {
	t.Parallel()
	ts := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	e := audit.Event{
		Timestamp: ts,
		Actor:     "test-actor",
		Backend:   "openai",
		Outcome:   audit.OutcomeOK,
		Action:    audit.ActionRead,
	}
	got := prettyEvent(e)
	if !strings.Contains(got, "2025-01-15") {
		t.Errorf("prettyEvent missing timestamp, got: %q", got)
	}
	if !strings.Contains(got, "test-actor") {
		t.Errorf("prettyEvent missing actor, got: %q", got)
	}
}

func TestPrettyEvent_EmptyFields(t *testing.T) {
	t.Parallel()
	e := audit.Event{
		Timestamp: time.Now(),
		Outcome:   audit.OutcomeDenied,
		Action:    audit.ActionList,
	}
	got := prettyEvent(e)
	// Empty actor and backend should render as "-"
	if !strings.Contains(got, "-") {
		t.Errorf("prettyEvent with empty fields should contain '-', got: %q", got)
	}
}

func TestLoadRetentionDays_NonExistentConfig(t *testing.T) {
	t.Parallel()
	// Non-existent path: should return default of 30.
	got := loadRetentionDays("/nonexistent/path/to/config.json")
	if got != 30 {
		t.Errorf("loadRetentionDays(nonexistent) = %d, want 30", got)
	}
}

func TestLoadRetentionDays_WithConfig(t *testing.T) {
	t.Parallel()
	// Write a config with retention_days set.
	dir := t.TempDir()
	cfgPath := dir + "/config.json"
	cfg := config.Config{Version: 1}
	cfg.Audit.RetentionDays = 60
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	got := loadRetentionDays(cfgPath)
	if got != 60 {
		t.Errorf("loadRetentionDays = %d, want 60", got)
	}
}

func TestLoadRetentionDays_ZeroRetentionDays(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := dir + "/config.json"
	cfg := config.Config{Version: 1}
	cfg.Audit.RetentionDays = 0
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	got := loadRetentionDays(cfgPath)
	if got != 30 {
		t.Errorf("loadRetentionDays(0 days) = %d, want default 30", got)
	}
}

// ---------------------------------------------------------------------------
// approve_cmd.go — formatTTL
// ---------------------------------------------------------------------------

func TestFormatTTL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "expired"},
		{0, "expired"},
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m30s"},
		{61 * time.Second, "1m1s"},
		{2*time.Hour + 15*time.Minute, "2h15m"},
		{time.Hour, "1h0m"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()
			got := formatTTL(tc.d)
			if got != tc.want {
				t.Errorf("formatTTL(%v) = %q, want %q", tc.d, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// cmd_backup.go — backupSanitizePath
// ---------------------------------------------------------------------------

func TestBackupSanitizePath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"default/ai/openrouter/api_key", "default_ai_openrouter_api_key"},
		{"simple", "simple"},
		{"a/b/c", "a_b_c"},
		{"traversal/../evil", "__invalid__"},
		{"../etc/passwd", "__invalid__"},
		{"ok/path/here", "ok_path_here"},
		{"", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got := backupSanitizePath(tc.in)
			if got != tc.want {
				t.Errorf("backupSanitizePath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// cmd_call.go — parseParamFlags, zeroBytes, baseURLFromTemplate
// ---------------------------------------------------------------------------

func TestParseParamFlags_Valid(t *testing.T) {
	t.Parallel()
	got, err := parseParamFlags([]string{"a=1", "b=2"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["a"] != "1" || got["b"] != "2" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestParseParamFlags_ValueWithEquals(t *testing.T) {
	t.Parallel()
	got, err := parseParamFlags([]string{"url=http://x?a=1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["url"] != "http://x?a=1" {
		t.Errorf("unexpected result: %v", got)
	}
}

func TestParseParamFlags_MissingEquals(t *testing.T) {
	t.Parallel()
	_, err := parseParamFlags([]string{"noequals"})
	if err == nil {
		t.Error("expected error for missing '='")
	}
}

func TestParseParamFlags_Empty(t *testing.T) {
	t.Parallel()
	got, err := parseParamFlags(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestZeroBytes(t *testing.T) {
	t.Parallel()
	b := []byte{1, 2, 3, 4, 5}
	zeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("b[%d] = %d, want 0", i, v)
		}
	}
}

func TestZeroBytes_NilAndEmpty(t *testing.T) {
	t.Parallel()
	// Should not panic.
	zeroBytes(nil)
	zeroBytes([]byte{})
}

func TestBaseURLFromTemplate_Valid(t *testing.T) {
	t.Parallel()
	// Call the real function via a ConnectionTemplate with a test endpoint.
	// baseURLFromTemplate parses tmpl.TestStrategy.Endpoint.
	tmpl := registry.ConnectionTemplate{}
	tmpl.TestStrategy.Endpoint = "https://api.example.com/v1/chat"
	got, err := baseURLFromTemplate(tmpl)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://api.example.com" {
		t.Errorf("got %q, want https://api.example.com", got)
	}
}

func TestBaseURLFromTemplate_NoHost(t *testing.T) {
	t.Parallel()
	tmpl := registry.ConnectionTemplate{}
	tmpl.TestStrategy.Endpoint = "/relative/path"
	_, err := baseURLFromTemplate(tmpl)
	if err == nil {
		t.Error("expected error for URL without host")
	}
}

func TestBaseURLFromTemplate_EmptyEndpoint(t *testing.T) {
	t.Parallel()
	tmpl := registry.ConnectionTemplate{}
	// Empty endpoint — TestStrategy.Endpoint is ""
	_, err := baseURLFromTemplate(tmpl)
	if err == nil {
		t.Error("expected error for empty endpoint")
	}
}

// ---------------------------------------------------------------------------
// cmd_status.go — relativeTime
// ---------------------------------------------------------------------------

func TestRelativeTime_Nil(t *testing.T) {
	t.Parallel()
	got := relativeTime(nil)
	if got != "never" {
		t.Errorf("relativeTime(nil) = %q, want 'never'", got)
	}
}

func TestRelativeTime_SecondsAgo(t *testing.T) {
	t.Parallel()
	recent := time.Now().Add(-10 * time.Second)
	got := relativeTime(&recent)
	if got != "just now" {
		t.Errorf("relativeTime(10s ago) = %q, want 'just now'", got)
	}
}

func TestRelativeTime_Future(t *testing.T) {
	t.Parallel()
	future := time.Now().Add(10 * time.Second)
	got := relativeTime(&future)
	if got != "just now" {
		t.Errorf("relativeTime(future) = %q, want 'just now'", got)
	}
}

func TestRelativeTime_MinutesAgo(t *testing.T) {
	t.Parallel()
	ago := time.Now().Add(-5 * time.Minute)
	got := relativeTime(&ago)
	if !strings.Contains(got, "m ago") {
		t.Errorf("relativeTime(5m ago) = %q, want contains 'm ago'", got)
	}
}

func TestRelativeTime_HoursAgo(t *testing.T) {
	t.Parallel()
	ago := time.Now().Add(-3 * time.Hour)
	got := relativeTime(&ago)
	if !strings.Contains(got, "h ago") {
		t.Errorf("relativeTime(3h ago) = %q, want contains 'h ago'", got)
	}
}

func TestRelativeTime_DaysAgo(t *testing.T) {
	t.Parallel()
	ago := time.Now().Add(-48 * time.Hour)
	got := relativeTime(&ago)
	if !strings.Contains(got, "d ago") {
		t.Errorf("relativeTime(48h ago) = %q, want contains 'd ago'", got)
	}
}

// ---------------------------------------------------------------------------
// grant_cmd.go — generateUUID
// ---------------------------------------------------------------------------

func TestGenerateUUID_Format(t *testing.T) {
	t.Parallel()
	id, err := generateUUID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// UUID v4 format: 8-4-4-4-12 hex chars = 36 total including dashes.
	if len(id) != 36 {
		t.Errorf("UUID length = %d, want 36; got %q", len(id), id)
	}
	parts := strings.Split(id, "-")
	if len(parts) != 5 {
		t.Errorf("UUID must have 5 parts separated by '-', got %q", id)
	}
}

func TestGenerateUUID_Unique(t *testing.T) {
	t.Parallel()
	id1, _ := generateUUID()
	id2, _ := generateUUID()
	if id1 == id2 {
		t.Error("two consecutive generateUUID calls returned the same value")
	}
}

// ---------------------------------------------------------------------------
// json_output.go — printJSON
// ---------------------------------------------------------------------------

func TestPrintJSON_Valid(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printJSON(&buf, map[string]string{"key": "value"})
	out := buf.String()
	if !strings.Contains(out, "key") || !strings.Contains(out, "value") {
		t.Errorf("expected JSON output to contain key/value, got: %s", out)
	}
}

func TestPrintJSON_Unencodable(t *testing.T) {
	t.Parallel()
	// channels cannot be marshalled to JSON.
	var buf bytes.Buffer
	printJSON(&buf, make(chan int))
	out := buf.String()
	if !strings.Contains(out, "error") {
		t.Errorf("expected error fallback in output, got: %s", out)
	}
}

func TestPrintJSON_Nil(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	printJSON(&buf, nil)
	out := buf.String()
	if out == "" {
		t.Error("expected non-empty output for nil value")
	}
}

// ---------------------------------------------------------------------------
// check_expiry_cmd.go — truncateAccessor
// ---------------------------------------------------------------------------

func TestTruncateAccessor(t *testing.T) {
	t.Parallel()
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"abcdefgh", 5, "abcde"},
		{"abc", 5, "abc"},
		{"abc", 3, "abc"},
		{"", 5, ""},
		{"hello", 0, ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%q/%d", tc.s, tc.n), func(t *testing.T) {
			t.Parallel()
			got := truncateAccessor(tc.s, tc.n)
			if got != tc.want {
				t.Errorf("truncateAccessor(%q, %d) = %q, want %q", tc.s, tc.n, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// config_cmd.go — getField, setField, printConfig, loadOrDefault, unwrapErr
// ---------------------------------------------------------------------------

func TestGetField_KnownKey(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Backend: "file", DefaultNamespace: "default"}
	val, found := getField(cfg, "backend")
	if !found {
		t.Error("expected to find 'backend' field")
	}
	if val != "file" {
		t.Errorf("getField backend = %q, want 'file'", val)
	}
}

func TestGetField_UnknownKey(t *testing.T) {
	t.Parallel()
	cfg := config.Config{}
	_, found := getField(cfg, "nonexistent_key")
	if found {
		t.Error("expected not found for nonexistent key")
	}
}

func TestGetField_CaseInsensitive(t *testing.T) {
	t.Parallel()
	cfg := config.Config{Backend: "keychain"}
	val, found := getField(cfg, "BACKEND")
	if !found {
		t.Error("expected to find 'BACKEND' (case-insensitive)")
	}
	if val != "keychain" {
		t.Errorf("getField BACKEND = %q, want 'keychain'", val)
	}
}

func TestSetField_Valid(t *testing.T) {
	t.Parallel()
	cfg := config.Config{}
	err := setField(&cfg, "backend", "keychain")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Backend != "keychain" {
		t.Errorf("Backend = %q, want 'keychain'", cfg.Backend)
	}
}

func TestSetField_UnknownKey(t *testing.T) {
	t.Parallel()
	cfg := config.Config{}
	err := setField(&cfg, "nonexistent_key", "value")
	if err == nil {
		t.Error("expected error for unknown key")
	}
}

func TestSetField_DefaultNamespace(t *testing.T) {
	t.Parallel()
	cfg := config.Config{}
	err := setField(&cfg, "default_namespace", "myns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DefaultNamespace != "myns" {
		t.Errorf("DefaultNamespace = %q, want 'myns'", cfg.DefaultNamespace)
	}
}

func TestPrintConfig_ContainsFields(t *testing.T) {
	t.Parallel()
	cmd := newConfigListCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cfg := config.Config{Backend: "file", DefaultNamespace: "myns"}
	printConfig(cmd, cfg)
	out := buf.String()
	if !strings.Contains(out, "backend") {
		t.Errorf("printConfig output missing 'backend': %s", out)
	}
}

func TestLoadOrDefault_NonExistentPath(t *testing.T) {
	t.Parallel()
	cfg, err := loadOrDefault("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should return a default config.
	_ = cfg
}

func TestUnwrapErr_Nil(t *testing.T) {
	t.Parallel()
	got := unwrapErr(nil)
	if got != nil {
		t.Errorf("unwrapErr(nil) = %v, want nil", got)
	}
}

func TestUnwrapErr_WrappedError(t *testing.T) {
	t.Parallel()
	base := errors.New("base")
	wrapped := fmt.Errorf("wrapped: %w", base)
	got := unwrapErr(wrapped)
	if got == nil {
		t.Fatal("expected non-nil result for wrapped error")
	}
	// The unwrapped result should be the base error (non-wrapping).
	if got.Error() != "base" {
		t.Errorf("unwrapErr result = %q, want 'base'", got.Error())
	}
}

func TestUnwrapErr_NotWrapped(t *testing.T) {
	t.Parallel()
	base := errors.New("raw")
	got := unwrapErr(base)
	// A non-wrapping error returns itself.
	if got != base {
		t.Errorf("unwrapErr(non-wrapped) = %v, want original error", got)
	}
}

// ---------------------------------------------------------------------------
// bootstrap_cmd.go — ParseBootstrapPlan
// ---------------------------------------------------------------------------

func TestParseBootstrapPlan_ValidJSON(t *testing.T) {
	t.Parallel()
	// Minimal valid JSON for a bootstrap.Plan (empty plan).
	data := []byte(`{}`)
	plan, err := ParseBootstrapPlan(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = plan
}

func TestParseBootstrapPlan_InvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ParseBootstrapPlan([]byte(`not-json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseBootstrapPlan_EmptyInput(t *testing.T) {
	t.Parallel()
	_, err := ParseBootstrapPlan([]byte{})
	if err == nil {
		t.Error("expected error for empty input")
	}
}

// ---------------------------------------------------------------------------
// check_expiry_cmd.go — outputCheckExpiryTable (via cobra command buffer)
// ---------------------------------------------------------------------------

func TestOutputCheckExpiryTable_Empty(t *testing.T) {
	t.Parallel()
	cmd := newCheckExpiryCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	outputCheckExpiryTable(cmd, nil)
	out := buf.String()
	if !strings.Contains(out, "No expiring") {
		t.Errorf("expected 'No expiring' message, got: %q", out)
	}
}

func TestOutputCheckExpiryTable_WithEntries(t *testing.T) {
	t.Parallel()
	cmd := newCheckExpiryCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	entries := []checkExpiryEntry{
		{Path: "default/ai/openrouter/api_key", Accessor: "abc123", DaysRemaining: -1, Status: "expired"},
	}
	outputCheckExpiryTable(cmd, entries)
	out := buf.String()
	if !strings.Contains(out, "openrouter") {
		t.Errorf("expected 'openrouter' in output, got: %q", out)
	}
	if !strings.Contains(out, "expired") {
		t.Errorf("expected 'expired' status in output, got: %q", out)
	}
}

func TestOutputCheckExpiryJSON(t *testing.T) {
	t.Parallel()
	cmd := newCheckExpiryCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	entries := []checkExpiryEntry{
		{Path: "default/test/key", DaysRemaining: 5, Status: "expiring-soon"},
	}
	if err := outputCheckExpiryJSON(cmd, entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "default/test/key") {
		t.Errorf("expected path in JSON output, got: %q", out)
	}
}

func TestOutputCheckExpiryJSON_NilEntries(t *testing.T) {
	t.Parallel()
	cmd := newCheckExpiryCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	if err := outputCheckExpiryJSON(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	// nil entries should produce "[]".
	if !strings.Contains(out, "[]") {
		t.Errorf("expected '[]' for nil entries, got: %q", out)
	}
}
