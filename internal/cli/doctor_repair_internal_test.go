package cli

// doctor_repair_internal_test.go tests runDoctorRepair's branching logic
// directly (H1). Internal test package (cli, not cli_test) so it can call
// the unexported runDoctorRepair/repairableChecks.
//
// IMPORTANT: none of these tests exercise the actual keychain-repair
// success path. RepairACL reads/writes the LOGIN keychain's
// "keylatch-keychain"/"unlock" item with no path scoping (not the
// project's custom keychain-db) — overriding HOME or KEYLATCH_CONFIG_DIR
// does NOT sandbox it away from the real login keychain. Per the hard
// constraint against running `security` against a real login keychain in
// tests, only the safe branches (healthy check skipped, non-repairable
// check message, and declined-confirmation) are covered here.

import (
	"bufio"
	"bytes"
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envWithBackend writes a config.json with the given backend to a temp
// KEYLATCH_CONFIG_DIR and returns an env Lookup pointing at it — used to
// control keychainACLRepairApplies's gate deterministically instead of
// depending on whatever config happens to exist on the machine running the
// test (review Finding-004 fix must not accidentally read the real config).
func envWithBackend(t *testing.T, backendName string) func(string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, config.Save(filepath.Join(dir, "config.json"), config.Config{
		Version:          1,
		Backend:          backendName,
		DefaultNamespace: "default",
	}))
	return func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	}
}

// withMockedStdin temporarily replaces the shared readLine() scanner with
// one reading from input, restoring it on test cleanup.
func withMockedStdin(t *testing.T, input string) {
	t.Helper()
	oldScannerFn := stdinScannerFn
	t.Cleanup(func() {
		stdinScannerFn = oldScannerFn
		scannerOnce = &sync.Once{}
		sharedScanner = nil
	})
	scannerOnce = &sync.Once{}
	sharedScanner = nil
	stdinScannerFn = func() *bufio.Scanner {
		return bufio.NewScanner(strings.NewReader(input))
	}
}

// TestRunDoctorRepair_HealthyCheck_Skipped verifies that a passing check
// (OK, no Warn) is left alone — no message, no repair attempt.
func TestRunDoctorRepair_HealthyCheck_Skipped(t *testing.T) {
	report := doctor.Report{
		Checks: []doctor.Status{
			{Name: "F1 bootstrap.keyring", OK: true},
		},
	}

	var stdout, stderr bytes.Buffer
	got := runDoctorRepair(context.Background(), &stdout, &stderr, report, func(string) string { return "" }, true)

	assert.Empty(t, stdout.String())
	assert.Empty(t, stderr.String())
	assert.Equal(t, report, got, "healthy-only report must be returned unchanged")
}

// TestRunDoctorRepair_NonRepairableCheck_PrintsNoAutomatedRepair verifies
// that a failing/warning check with no known repair prints the "no
// automated repair" message with its existing Fix hint, and does not
// attempt any repair.
func TestRunDoctorRepair_NonRepairableCheck_PrintsNoAutomatedRepair(t *testing.T) {
	report := doctor.Report{
		Checks: []doctor.Status{
			{
				Name:   "backend.file",
				OK:     false,
				Detail: "vault_dir not found",
				Fix:    "Run `keylatch bootstrap` to create the vault directory.",
			},
		},
	}

	var stdout, stderr bytes.Buffer
	got := runDoctorRepair(context.Background(), &stdout, &stderr, report, func(string) string { return "" }, true)

	assert.Contains(t, stdout.String(), "no automated repair")
	assert.Contains(t, stdout.String(), "backend.file")
	assert.Contains(t, stdout.String(), "keylatch bootstrap")
	assert.Empty(t, stderr.String())
	assert.Equal(t, report, got, "no repair attempted -> report unchanged")
}

// TestRunDoctorRepair_RepairableCheck_DeclinedPrompt verifies that without
// --yes, declining the confirmation prompt skips the repair entirely (the
// unsafe repairKeychainACL call is never reached). Uses a config with
// backend=keychain so the review Finding-004 gate lets the prompt appear at
// all (this test's whole point is the decline path, not the gate).
func TestRunDoctorRepair_RepairableCheck_DeclinedPrompt(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("keychain backend is darwin-only; the Finding-004 gate always skips it elsewhere")
	}
	withMockedStdin(t, "n\n")

	report := doctor.Report{
		Checks: []doctor.Status{
			{
				Name:   "acl.keychain_unlock",
				OK:     true,
				Warn:   true,
				Detail: "keychain ACL: mismatch",
				Fix:    "Run `keylatch keychain-repair-acl` to repair the ACL.",
			},
		},
	}

	var stdout, stderr bytes.Buffer
	got := runDoctorRepair(context.Background(), &stdout, &stderr, report, envWithBackend(t, "keychain"), false /* yes=false: prompts */)

	assert.Contains(t, stdout.String(), "Repair acl.keychain_unlock")
	assert.Contains(t, stdout.String(), "skipped acl.keychain_unlock")
	assert.Empty(t, stderr.String())
	assert.Equal(t, report, got, "declined repair -> report unchanged, no re-run")
}

// TestRunDoctorRepair_KeychainACLCheck_SkippedWhenBackendNotKeychain is the
// review Finding-004 regression test: the ACL check itself only gates on
// whether a keychain-db file happens to exist on disk (checks_optional.go),
// not on whether keychain is the actively selected backend. A user who
// switched backends (H2) but has a leftover keychain-db file must not have
// --repair silently open and repair that orphaned keychain's ACL. No prompt
// should appear at all — the gate must short-circuit before the confirmation
// step.
func TestRunDoctorRepair_KeychainACLCheck_SkippedWhenBackendNotKeychain(t *testing.T) {
	report := doctor.Report{
		Checks: []doctor.Status{
			{
				Name:   "acl.keychain_unlock",
				OK:     true,
				Warn:   true,
				Detail: "keychain ACL: mismatch",
				Fix:    "Run `keylatch keychain-repair-acl` to repair the ACL.",
			},
		},
	}

	var stdout, stderr bytes.Buffer
	got := runDoctorRepair(context.Background(), &stdout, &stderr, report, envWithBackend(t, "file"), true /* yes=true — must still not repair */)

	assert.NotContains(t, stdout.String(), "Repair acl.keychain_unlock", "must not prompt when keychain isn't the active backend")
	assert.Contains(t, stdout.String(), "no automated repair")
	assert.Contains(t, stdout.String(), "unrelated to your active backend")
	assert.Empty(t, stderr.String())
	assert.Equal(t, report, got, "gated repair -> report unchanged, no re-run")
}

// TestKeychainACLRepairApplies_NonDarwin verifies the repair never applies
// on non-darwin platforms even if the config claims backend=keychain
// (which itself would be invalid there — checkBackendSelected would FAIL
// it — but the repair gate must not assume that check already ran).
func TestKeychainACLRepairApplies_NonDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this test is for non-darwin platforms only")
	}
	assert.False(t, keychainACLRepairApplies(envWithBackend(t, "keychain")))
}

// TestRepairableChecks_OnlyKeychainACL documents and locks in the
// intentionally narrow H1 repair scope.
func TestRepairableChecks_OnlyKeychainACL(t *testing.T) {
	assert.Equal(t, map[string]bool{"acl.keychain_unlock": true}, repairableChecks)
}
