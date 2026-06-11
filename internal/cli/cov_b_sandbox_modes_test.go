package cli

// cov_b_sandbox_modes_test.go — Agent B coverage for sandbox_cmd.go and modes_cmd.go.
// Tests for sandbox doctor, sandbox run, sandboxModeAvailability, and buildSandboxDoctorOutput.
// Hermetic: no network, no OS keychain.

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

// --- buildSandboxDoctorOutput ---

func TestCovB_BuildSandboxDoctorOutput_Windows(t *testing.T) {
	out := buildSandboxDoctorOutput("windows")
	if out.Available {
		t.Error("expected Available=false on Windows")
	}
	if out.Platform != "windows" {
		t.Errorf("expected Platform=windows, got: %s", out.Platform)
	}
	if out.Reason == "" {
		t.Error("expected non-empty Reason for Windows")
	}
}

func TestCovB_BuildSandboxDoctorOutput_Darwin(t *testing.T) {
	out := buildSandboxDoctorOutput("darwin")
	if !out.Available {
		t.Error("expected Available=true on darwin (sandbox-exec built-in)")
	}
	if out.Tool != "sandbox-exec" {
		t.Errorf("expected Tool=sandbox-exec on darwin, got: %s", out.Tool)
	}
}

func TestBuildSandboxDoctorOutput_Linux_NoBwrap(t *testing.T) {
	if runtime.GOOS == "linux" {
		// On actual Linux with bwrap, skip this test variant.
		t.Skip("skipping: may have bwrap on real Linux; check via command call instead")
	}
	out := buildSandboxDoctorOutput("linux")
	// Either available (bwrap found) or not — just check fields are populated.
	if out.Platform != "linux" {
		t.Errorf("expected Platform=linux, got: %s", out.Platform)
	}
	if out.Tool != "bwrap" {
		t.Errorf("expected Tool=bwrap on linux, got: %s", out.Tool)
	}
}

func TestBuildSandboxDoctorOutput_Unknown(t *testing.T) {
	// Unknown platforms fall through to the "macOS and other POSIX" branch.
	out := buildSandboxDoctorOutput("freebsd")
	if !out.Available {
		t.Error("expected Available=true for unknown POSIX platform")
	}
	if out.Tool != "sandbox-exec" {
		t.Errorf("expected Tool=sandbox-exec for unknown POSIX, got: %s", out.Tool)
	}
}

// --- sandboxModeAvailability ---

func TestSandboxModeAvailability_Windows(t *testing.T) {
	// We can only test the current platform's branch, so test via
	// buildSandboxDoctorOutput which calls the same logic.
	out := buildSandboxDoctorOutput("windows")
	// Should be unavailable.
	if out.Available {
		t.Error("expected sandbox unavailable on windows")
	}
}

func TestSandboxModeAvailability_CurrentPlatform(t *testing.T) {
	available, reason, _ := sandboxModeAvailability()
	if reason == "" {
		t.Error("expected non-empty reason from sandboxModeAvailability")
	}
	_ = available // result depends on system state
}

// --- newSandboxDoctorCmd (via root command) ---

func TestSandboxDoctorCmd_JSON(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sandbox", "doctor", "--json"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sandboxDoctorOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result); err != nil {
		t.Fatalf("JSON parse error: %v — output: %s", err, out.String())
	}
	if result.Platform == "" {
		t.Error("expected non-empty Platform in JSON output")
	}
}

func TestSandboxDoctorCmd_Text(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sandbox", "doctor"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out.String(), "sandbox doctor") {
		t.Errorf("expected 'sandbox doctor' in output, got: %s", out.String())
	}
}

func TestSandboxDoctorCmd_WithConnectionArg(t *testing.T) {
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sandbox", "doctor", "--json", "my-connection"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result sandboxDoctorOutput
	if err := json.Unmarshal([]byte(strings.TrimSpace(out.String())), &result); err != nil {
		t.Fatalf("JSON parse error: %v — output: %s", err, out.String())
	}
	// With a connection arg, reason should include the connection slug.
	if !strings.Contains(result.Reason, "connection=my-connection") {
		t.Errorf("expected 'connection=my-connection' in reason, got: %s", result.Reason)
	}
}

// --- newSandboxRunCmd ---

func TestSandboxRunCmd_MissingConnection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping: Windows returns different error path")
	}
	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sandbox", "run", "echo", "hello"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --connection is missing")
	}
	if !strings.Contains(err.Error(), "--connection") {
		t.Errorf("expected '--connection' in error, got: %v", err)
	}
}

func TestSandboxRunCmd_NotImplemented(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping: Windows returns different error path")
	}
	if runtime.GOOS == "linux" {
		// On Linux without bwrap this returns a different error.
		t.Skip("skipping on Linux: depends on bwrap availability")
	}
	root := NewRootCommand()
	root.SetOut(bytes.NewBuffer(nil))
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"sandbox", "run", "--connection", "my-conn", "echo"})

	err := root.Execute()
	if err == nil {
		t.Fatal("expected 'not yet implemented' error")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("expected 'not yet implemented' in error, got: %v", err)
	}
}

// --- newModesCmd ---

func TestModesCmd_JSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"modes", "--json"})

	// Execute — may exit non-zero if gateway unavailable; that is correct behaviour.
	_ = root.Execute()

	output := strings.TrimSpace(out.String())
	if output == "" {
		t.Fatal("expected non-empty JSON output from modes --json")
	}

	// Modes JSON is wrapped: {"_schema": "v1", "modes": [...]}.
	var wrapper struct {
		Schema string      `json:"_schema"`
		Modes  []ModeEntry `json:"modes"`
	}
	if err := json.Unmarshal([]byte(output), &wrapper); err != nil {
		t.Fatalf("JSON parse error: %v — output: %s", err, output)
	}
	if len(wrapper.Modes) == 0 {
		t.Error("expected at least one mode entry")
	}
}

func TestModesCmd_Text(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(bytes.NewBuffer(nil))
	root.SetArgs([]string{"modes"})

	_ = root.Execute()

	output := out.String()
	if !strings.Contains(output, "gateway_typed") {
		t.Errorf("expected 'gateway_typed' in modes output, got:\n%s", output)
	}
}
