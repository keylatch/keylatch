//go:build integration && linux

package integration_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// TestBrokerdSystemdHardening scores the shipped unit with systemd-analyze. It
// needs systemd 253 or newer and runs in the CI container that has it.
func TestBrokerdSystemdHardening(t *testing.T) {
	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze is not installed")
	}
	unit, err := filepath.Abs("../../packaging/linux/systemd/keylatchd.service")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(analyze, "security", "--offline=true", "--no-pager", unit).CombinedOutput() //nolint:gosec // G204: a fixed binary and the unit shipped in this repository
	if err != nil && len(out) == 0 {
		t.Skipf("systemd-analyze security --offline is not available: %v", err)
	}
	m := regexp.MustCompile(`Overall exposure level for [^:]+: ([0-9.]+)`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("no exposure level in the output:\n%s", out)
	}
	score, _ := strconv.ParseFloat(string(m[1]), 64)
	if score > 2.0 {
		t.Fatalf("keylatchd.service scores %.1f, want 2.0 or lower:\n%s", score, out)
	}
}
