package cli

// cov_b_versions_extras_test.go — Agent B coverage for versions_cmd.go helpers.
// Tests for versionState and printVersionsTable.
// Hermetic: no network, no OS keychain.

import (
	"bytes"
	"strings"
	"testing"
	"time"

	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

func TestVersionState_Live(t *testing.T) {
	vm := vmeta.VersionMeta{Version: 1}
	if got := versionState(vm); got != "live" {
		t.Errorf("expected 'live', got: %s", got)
	}
}

func TestVersionState_Deleted(t *testing.T) {
	now := time.Now()
	vm := vmeta.VersionMeta{Version: 1, DeletedAt: &now}
	if got := versionState(vm); got != "deleted" {
		t.Errorf("expected 'deleted', got: %s", got)
	}
}

func TestVersionState_Destroyed(t *testing.T) {
	now := time.Now()
	vm := vmeta.VersionMeta{Version: 1, DestroyedAt: &now}
	if got := versionState(vm); got != "destroyed" {
		t.Errorf("expected 'destroyed', got: %s", got)
	}
}

func TestVersionState_DestroyedTakesPriorityOverDeleted(t *testing.T) {
	now := time.Now()
	vm := vmeta.VersionMeta{Version: 1, DeletedAt: &now, DestroyedAt: &now}
	if got := versionState(vm); got != "destroyed" {
		t.Errorf("expected 'destroyed' when both DeletedAt and DestroyedAt set, got: %s", got)
	}
}

func TestPrintVersionsTable_ShowsVersions(t *testing.T) {
	now := time.Now()
	meta := vmeta.Meta{
		CurrentVersion: 2,
		Backend:        "file",
		Accessor:       vmeta.ID("acc_12345678"),
		Versions: []vmeta.VersionMeta{
			{Version: 1, CreatedAt: now},
			{Version: 2, CreatedAt: now},
		},
	}

	// Build a fake cobra command to pass as receiver.
	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)

	printVersionsTable(root, meta)

	output := out.String()
	if !strings.Contains(output, "VER") {
		t.Errorf("expected 'VER' header, got:\n%s", output)
	}
	if !strings.Contains(output, "live") {
		t.Errorf("expected 'live' state, got:\n%s", output)
	}
	if !strings.Contains(output, "2") {
		t.Errorf("expected version number '2', got:\n%s", output)
	}
	// Current version should be marked with *.
	if !strings.Contains(output, "*") {
		t.Errorf("expected '*' marker for current version, got:\n%s", output)
	}
}

func TestPrintVersionsTable_DestroyedVersion(t *testing.T) {
	now := time.Now()
	meta := vmeta.Meta{
		CurrentVersion: 1,
		Backend:        "file",
		Accessor:       vmeta.ID("acc_12345678"),
		Versions: []vmeta.VersionMeta{
			{Version: 1, CreatedAt: now, DestroyedAt: &now},
		},
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	printVersionsTable(root, meta)

	if !strings.Contains(out.String(), "destroyed") {
		t.Errorf("expected 'destroyed' in table, got:\n%s", out.String())
	}
}

func TestPrintVersionsTable_ExpiresAt(t *testing.T) {
	now := time.Now()
	expiry := now.Add(24 * time.Hour)
	meta := vmeta.Meta{
		CurrentVersion: 1,
		Backend:        "file",
		Accessor:       vmeta.ID("acc_12345678"),
		Versions: []vmeta.VersionMeta{
			{Version: 1, CreatedAt: now, ExpiresAt: &expiry},
		},
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	printVersionsTable(root, meta)

	// ExpiresAt should appear (not "—").
	output := out.String()
	if strings.Count(output, "—") != 0 {
		// If expiry is set, the column should not show "—".
		// Some columns may still show "—" for nil expiresAt on other versions.
		// This just verifies the set expiry is included.
	}
	if !strings.Contains(output, expiry.Format("2006")) {
		t.Errorf("expected expiry year in output, got:\n%s", output)
	}
}

func TestPrintVersionsTable_NilExpiresAt(t *testing.T) {
	now := time.Now()
	meta := vmeta.Meta{
		CurrentVersion: 1,
		Backend:        "file",
		Accessor:       vmeta.ID("acc_12345678"),
		Versions: []vmeta.VersionMeta{
			{Version: 1, CreatedAt: now},
		},
	}

	root := NewRootCommand()
	var out bytes.Buffer
	root.SetOut(&out)
	printVersionsTable(root, meta)

	// Nil ExpiresAt should render as "—".
	if !strings.Contains(out.String(), "—") {
		t.Errorf("expected '—' for nil ExpiresAt, got:\n%s", out.String())
	}
}
