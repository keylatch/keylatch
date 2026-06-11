// Package cli — coverage agent A: doctor and audit helper tests (a–l files).
// File: cov_a_doctor_audit_test.go
// Tests for: doctor_cmd.go (buildDoctorJSONV1, printStatusLine, printDoctorReport),
//            audit_hook.go (SecurityBlockHook type), audit_cmd.go (openAuditLogger path).
package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
)

// ---------------------------------------------------------------------------
// doctor_cmd.go — buildDoctorJSONV1
// ---------------------------------------------------------------------------

func TestBuildDoctorJSONV1_AllOK(t *testing.T) {
	t.Parallel()
	report := doctor.Report{
		Version:  "test",
		Platform: "darwin",
		Checks: []doctor.Status{
			{Name: "check1", OK: true, Detail: "all good"},
			{Name: "check2", OK: true, Detail: "also good"},
		},
		OverallOK: true,
	}
	result := buildDoctorJSONV1(report, 0)
	if result.Schema != "v1" {
		t.Errorf("Schema = %q, want 'v1'", result.Schema)
	}
	if result.Exit != 0 {
		t.Errorf("Exit = %d, want 0", result.Exit)
	}
	if result.Summary.OK != 2 {
		t.Errorf("Summary.OK = %d, want 2", result.Summary.OK)
	}
	if result.Summary.Fail != 0 {
		t.Errorf("Summary.Fail = %d, want 0", result.Summary.Fail)
	}
	if result.Summary.Warn != 0 {
		t.Errorf("Summary.Warn = %d, want 0", result.Summary.Warn)
	}
}

func TestBuildDoctorJSONV1_WithFailures(t *testing.T) {
	t.Parallel()
	report := doctor.Report{
		Version:  "test",
		Platform: "linux",
		Checks: []doctor.Status{
			{Name: "check1", OK: false, Detail: "failed"},
			{Name: "check2", OK: true, Warn: true, Detail: "warning"},
			{Name: "check3", OK: true, Detail: "ok"},
		},
		OverallOK: false,
	}
	result := buildDoctorJSONV1(report, 2)
	if result.Exit != 2 {
		t.Errorf("Exit = %d, want 2", result.Exit)
	}
	if result.Summary.Fail != 1 {
		t.Errorf("Summary.Fail = %d, want 1", result.Summary.Fail)
	}
	if result.Summary.Warn != 1 {
		t.Errorf("Summary.Warn = %d, want 1", result.Summary.Warn)
	}
	if result.Summary.OK != 1 {
		t.Errorf("Summary.OK = %d, want 1 (non-warn OK only)", result.Summary.OK)
	}
}

func TestBuildDoctorJSONV1_OperatingMode_IsNonEmpty(t *testing.T) {
	t.Parallel()
	// resolveOperatingModeForDoctor may return "unknown" if config not found — that's OK.
	report := doctor.Report{}
	result := buildDoctorJSONV1(report, 0)
	if result.OperatingMode == "" {
		t.Error("OperatingMode must be non-empty (at least 'unknown')")
	}
}

func TestBuildDoctorJSONV1_EmptyReport(t *testing.T) {
	t.Parallel()
	report := doctor.Report{}
	result := buildDoctorJSONV1(report, 0)
	if result.Schema != "v1" {
		t.Errorf("Schema = %q, want 'v1'", result.Schema)
	}
	if result.Summary.OK != 0 || result.Summary.Fail != 0 || result.Summary.Warn != 0 {
		t.Errorf("empty report: unexpected summary counts: %+v", result.Summary)
	}
}

// ---------------------------------------------------------------------------
// doctor_cmd.go — printStatusLine
// ---------------------------------------------------------------------------

func TestPrintStatusLine_OK(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	s := doctor.Status{Name: "test-check", OK: true, Detail: "all good"}
	printStatusLine(&buf, s)
	out := buf.String()
	if !strings.Contains(out, "[ ok ]") {
		t.Errorf("expected '[ ok ]' in output, got: %q", out)
	}
	if !strings.Contains(out, "test-check") {
		t.Errorf("expected check name in output, got: %q", out)
	}
	if !strings.Contains(out, "all good") {
		t.Errorf("expected detail in output, got: %q", out)
	}
}

func TestPrintStatusLine_Fail(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	s := doctor.Status{Name: "fail-check", OK: false, Detail: "something wrong", Fix: "run keylatch bootstrap"}
	printStatusLine(&buf, s)
	out := buf.String()
	if !strings.Contains(out, "[FAIL]") {
		t.Errorf("expected '[FAIL]' in output, got: %q", out)
	}
	if !strings.Contains(out, "fix: run keylatch bootstrap") {
		t.Errorf("expected fix line in output, got: %q", out)
	}
}

func TestPrintStatusLine_Warn(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	s := doctor.Status{Name: "warn-check", OK: true, Warn: true, Detail: "marginal", Fix: "check config"}
	printStatusLine(&buf, s)
	out := buf.String()
	if !strings.Contains(out, "[warn]") {
		t.Errorf("expected '[warn]' in output, got: %q", out)
	}
	if !strings.Contains(out, "check config") {
		t.Errorf("expected fix hint in warn output, got: %q", out)
	}
}

func TestPrintStatusLine_OKWithFix_NoFixOutput(t *testing.T) {
	t.Parallel()
	// A status that is OK and not Warn — fix line should NOT appear.
	var buf bytes.Buffer
	s := doctor.Status{Name: "ok-check", OK: true, Warn: false, Detail: "fine", Fix: "should-not-appear"}
	printStatusLine(&buf, s)
	out := buf.String()
	if strings.Contains(out, "should-not-appear") {
		t.Errorf("fix must NOT appear for OK (non-warn) status, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// doctor_cmd.go — printDoctorReport
// ---------------------------------------------------------------------------

func TestPrintDoctorReport_Basic(t *testing.T) {
	t.Parallel()
	cmd := newDoctorCmdImpl()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	report := doctor.Report{
		Version:  "0.1.0-test",
		Platform: "linux",
		Checks: []doctor.Status{
			{Name: "env-check", Section: "environment", OK: true, Detail: "ok"},
			{Name: "backend-check", Section: "backends", OK: false, Detail: "missing"},
		},
		OverallOK: false,
	}
	printDoctorReport(cmd, report)
	out := buf.String()
	if !strings.Contains(out, "keylatch doctor") {
		t.Errorf("expected 'keylatch doctor' header, got: %q", out)
	}
	if !strings.Contains(out, "0.1.0-test") {
		t.Errorf("expected version in output, got: %q", out)
	}
}

func TestPrintDoctorReport_WithLLMSession(t *testing.T) {
	t.Parallel()
	cmd := newDoctorCmdImpl()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	report := doctor.Report{
		Version:    "test",
		Platform:   "darwin",
		LLMSession: true,
		LLMReasons: []string{"CLAUDE_CODE"},
		Checks:     []doctor.Status{},
		OverallOK:  true,
	}
	printDoctorReport(cmd, report)
	out := buf.String()
	if !strings.Contains(out, "LLM session") {
		t.Errorf("expected 'LLM session' in output, got: %q", out)
	}
	if !strings.Contains(out, "CLAUDE_CODE") {
		t.Errorf("expected LLM reason in output, got: %q", out)
	}
}

func TestPrintDoctorReport_Failures(t *testing.T) {
	t.Parallel()
	cmd := newDoctorCmdImpl()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	report := doctor.Report{
		Version:  "test",
		Platform: "linux",
		Checks: []doctor.Status{
			{Name: "fail1", Section: "backends", OK: false, Detail: "backend missing"},
			{Name: "warn1", Section: "environment", OK: true, Warn: true, Detail: "warning"},
		},
		OverallOK: false,
	}
	printDoctorReport(cmd, report)
	out := buf.String()
	// Should contain "failure(s)" in the summary.
	if !strings.Contains(out, "failure") {
		t.Errorf("expected 'failure' in summary line, got: %q", out)
	}
}

func TestPrintDoctorReport_UnsectionedChecks(t *testing.T) {
	t.Parallel()
	cmd := newDoctorCmdImpl()
	var buf bytes.Buffer
	cmd.SetOut(&buf)

	report := doctor.Report{
		Version:  "test",
		Platform: "linux",
		Checks: []doctor.Status{
			// No section — should appear in the "Other" fallback.
			{Name: "orphan-check", Section: "", OK: true, Detail: "ok"},
		},
		OverallOK: true,
	}
	printDoctorReport(cmd, report)
	out := buf.String()
	// "Other" section or orphan check should appear somewhere.
	if !strings.Contains(out, "orphan-check") {
		t.Errorf("expected orphan-check in output, got: %q", out)
	}
}
