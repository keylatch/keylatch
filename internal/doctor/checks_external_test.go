package doctor_test

// checks_external_test.go — EPIC-10 tests for external PM CLI doctor checks.
//
// Tests:
//   - TestExternalOP_NoConnections_Skipped    — E1 check is skipped when no provider-ref connections exist
//   - TestExternalOP_BinaryNotFound_Fails     — E1 check fails when `op` is not on PATH
//   - TestExternalOP_BinaryFound_OK           — E1 check passes when `op` is found
//   - TestExternalAWSSM_NoConnections_Skipped — E2 check is skipped when no provider-ref connections
//   - TestExternalAWSSM_BinaryNotFound_Fails  — E2 check fails when `aws` is not on PATH
//   - TestExternalAWSSM_BinaryFound_OK        — E2 check passes when `aws` is found
//   - TestExternalHashiVault_NoConnections_Skipped — E3 check is skipped
//   - TestExternalHashiVault_BinaryNotFound_Fails  — E3 check fails when `vault` is not on PATH
//   - TestExternalHashiVault_BinaryFound_OK        — E3 check passes when `vault` is found
//   - TestExternalSection_InReport           — "external" section appears in doctor report

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
	kexec "github.com/keylatch/keylatch/internal/exec"
)

// writeProviderRefFile creates a fake vault field file containing an external
// reference URI to trigger the "has external ref connections" detection.
func writeProviderRefFile(t *testing.T, vaultDir, uri string) {
	t.Helper()
	dir := filepath.Join(vaultDir, "default", "ai", "anthropic")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "api_key"), []byte(uri), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// fakeEnvWithVault returns an env func that maps KEYLATCH_VAULT_PATH to vaultDir.
func fakeEnvWithVault(vaultDir string) func(string) string {
	return func(k string) string {
		if k == "KEYLATCH_VAULT_PATH" {
			return vaultDir
		}
		return ""
	}
}

// noRefEnv returns an env func that points to an empty vault dir (no connections).
func noRefEnv(t *testing.T) func(string) string {
	t.Helper()
	return fakeEnvWithVault(t.TempDir())
}

// --- E1: op:// checks ---

func TestExternalOP_NoConnections_Skipped(t *testing.T) {
	t.Parallel()
	env := noRefEnv(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	var found *doctor.Status
	for i := range report.Checks {
		if report.Checks[i].Name == "external.op" {
			found = &report.Checks[i]
			break
		}
	}
	if found == nil {
		t.Fatal("external.op check not found in report")
	}
	if !found.OK {
		t.Errorf("external.op: expected OK=true (skipped), got OK=false")
	}
	if found.Section != "external" {
		t.Errorf("external.op section: got %q, want %q", found.Section, "external")
	}
}

func TestExternalOP_BinaryNotFound_Fails(t *testing.T) {
	t.Parallel()
	vaultDir := t.TempDir()
	writeProviderRefFile(t, vaultDir, "op://Private/Anthropic/api_key")
	env := fakeEnvWithVault(vaultDir)

	// Probe that does NOT find `op`.
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	var found *doctor.Status
	for i := range report.Checks {
		if report.Checks[i].Name == "external.op" {
			found = &report.Checks[i]
			break
		}
	}
	if found == nil {
		t.Fatal("external.op check not found in report")
	}
	if found.OK {
		t.Errorf("external.op: expected OK=false (binary not found), got OK=true")
	}
	if found.Fix == "" {
		t.Error("external.op: expected non-empty Fix hint when binary not found")
	}
}

func TestExternalOP_BinaryFound_OK(t *testing.T) {
	t.Parallel()
	vaultDir := t.TempDir()
	writeProviderRefFile(t, vaultDir, "op://Private/Anthropic/api_key")
	env := fakeEnvWithVault(vaultDir)

	probe := newMockProbe()
	probe.found["op"] = "/usr/local/bin/op"
	probe.version["/usr/local/bin/op"] = "2.30.0"

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	var found *doctor.Status
	for i := range report.Checks {
		if report.Checks[i].Name == "external.op" {
			found = &report.Checks[i]
			break
		}
	}
	if found == nil {
		t.Fatal("external.op check not found in report")
	}
	if !found.OK {
		t.Errorf("external.op: expected OK=true, got OK=false; detail=%q", found.Detail)
	}
}

// --- E2: aws-sm:// checks ---

func TestExternalAWSSM_NoConnections_Skipped(t *testing.T) {
	t.Parallel()
	env := noRefEnv(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	for _, s := range report.Checks {
		if s.Name == "external.aws-sm" {
			if !s.OK {
				t.Errorf("external.aws-sm: expected skipped (OK=true), got OK=false")
			}
			return
		}
	}
	t.Fatal("external.aws-sm check not found in report")
}

func TestExternalAWSSM_BinaryNotFound_Fails(t *testing.T) {
	t.Parallel()
	vaultDir := t.TempDir()
	writeProviderRefFile(t, vaultDir, "aws-sm://us-east-1/my-secret")
	env := fakeEnvWithVault(vaultDir)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	for _, s := range report.Checks {
		if s.Name == "external.aws-sm" {
			if s.OK {
				t.Errorf("external.aws-sm: expected OK=false (binary not found)")
			}
			if s.Fix == "" {
				t.Error("external.aws-sm: expected Fix hint")
			}
			return
		}
	}
	t.Fatal("external.aws-sm check not found in report")
}

func TestExternalAWSSM_BinaryFound_OK(t *testing.T) {
	t.Parallel()
	vaultDir := t.TempDir()
	writeProviderRefFile(t, vaultDir, "aws-sm://us-east-1/my-secret")
	env := fakeEnvWithVault(vaultDir)

	probe := newMockProbe()
	probe.found["aws"] = "/usr/local/bin/aws"
	probe.version["/usr/local/bin/aws"] = "2.15.0"

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	for _, s := range report.Checks {
		if s.Name == "external.aws-sm" {
			if !s.OK {
				t.Errorf("external.aws-sm: expected OK=true, got OK=false; detail=%q", s.Detail)
			}
			return
		}
	}
	t.Fatal("external.aws-sm check not found in report")
}

// --- E3: hashivault:// checks ---

func TestExternalHashiVault_NoConnections_Skipped(t *testing.T) {
	t.Parallel()
	env := noRefEnv(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	for _, s := range report.Checks {
		if s.Name == "external.hashivault" {
			if !s.OK {
				t.Errorf("external.hashivault: expected skipped (OK=true)")
			}
			return
		}
	}
	t.Fatal("external.hashivault check not found in report")
}

func TestExternalHashiVault_BinaryNotFound_Fails(t *testing.T) {
	t.Parallel()
	vaultDir := t.TempDir()
	writeProviderRefFile(t, vaultDir, "hashivault://secret/myapp/config")
	env := fakeEnvWithVault(vaultDir)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	for _, s := range report.Checks {
		if s.Name == "external.hashivault" {
			if s.OK {
				t.Errorf("external.hashivault: expected OK=false (binary not found)")
			}
			if s.Fix == "" {
				t.Error("external.hashivault: expected Fix hint")
			}
			return
		}
	}
	t.Fatal("external.hashivault check not found in report")
}

func TestExternalHashiVault_BinaryFound_OK(t *testing.T) {
	t.Parallel()
	vaultDir := t.TempDir()
	writeProviderRefFile(t, vaultDir, "hashivault://secret/myapp/config")
	env := fakeEnvWithVault(vaultDir)

	probe := newMockProbe()
	probe.found["vault"] = "/usr/local/bin/vault"
	probe.version["/usr/local/bin/vault"] = "1.17.0"

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	for _, s := range report.Checks {
		if s.Name == "external.hashivault" {
			if !s.OK {
				t.Errorf("external.hashivault: expected OK=true, got OK=false; detail=%q", s.Detail)
			}
			return
		}
	}
	t.Fatal("external.hashivault check not found in report")
}

// --- Section appearance ---

func TestExternalSection_InReport(t *testing.T) {
	t.Parallel()
	env := noRefEnv(t)
	probe := newMockProbe()

	report, err := doctor.Run(context.Background(), doctor.Options{
		Verbose: true,
		Env:     env,
		Probe:   probe,
	})
	if err != nil {
		t.Fatalf("doctor.Run: %v", err)
	}

	// The "external" section must appear in the Sections summary.
	for _, sec := range report.Sections {
		if sec.Name == "external" {
			return
		}
	}
	t.Error("'external' section not found in report.Sections — checks_external.go may not be wired in")
}

// Compile-time assertion: doctor.Status is exported (used in table iteration above).
var _ doctor.Status
var _ kexec.Probe
