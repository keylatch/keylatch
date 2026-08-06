//go:build darwin

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallLaunchdPlist_WritesPlistWithCorrectContentAndPerms verifies
// installLaunchdPlist writes a plist with the expected label, resolved
// keylatchd path, RunAtLoad/KeepAlive keys, log paths, and file mode —
// without ever shelling out to launchctl (installLaunchdPlist never calls
// it; only newGatewayInstallCmd's separate launchctl-load step does).
func TestInstallLaunchdPlist_WritesPlistWithCorrectContentAndPerms(t *testing.T) {
	// Put a fake, non-executing "keylatchd" binary on PATH so findKeylatchd's
	// PATH-lookup fallback resolves deterministically — installLaunchdPlist
	// never runs it, only records its resolved path in the plist.
	binDir := t.TempDir()
	fakeKeylatchd := filepath.Join(binDir, "keylatchd")
	if err := os.WriteFile(fakeKeylatchd, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake keylatchd: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	plistDir := t.TempDir()
	plistPath := filepath.Join(plistDir, "io.keylatch.keylatchd.plist")

	if err := installLaunchdPlist(plistPath); err != nil {
		t.Fatalf("installLaunchdPlist: %v", err)
	}

	info, statErr := os.Stat(plistPath)
	if statErr != nil {
		t.Fatalf("stat plist: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("plist permissions: got %o, want %o", perm, 0o644)
	}

	content, readErr := os.ReadFile(plistPath)
	if readErr != nil {
		t.Fatalf("read plist: %v", readErr)
	}
	s := string(content)
	for _, want := range []string{
		"<key>Label</key><string>io.keylatch.keylatchd</string>",
		fakeKeylatchd, // ProgramArguments must reference the resolved keylatchd path
		"<key>RunAtLoad</key><true/>",
		"<key>KeepAlive</key><true/>",
		"Library/Logs/keylatchd.log",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("plist content missing %q\ngot:\n%s", want, s)
		}
	}
}

// TestNewGatewayInstallCmd_RefusesWhenDesktopAppRunning verifies the
// port-7890-conflict guard: when desktopAppRunningFunc reports Keylatch.app
// already owns the daemon, `gateway install` must return early without ever
// touching the real ~/Library/LaunchAgents plist path or invoking
// launchctl — launchctlRunFunc is set to fail the test if called at all.
func TestNewGatewayInstallCmd_RefusesWhenDesktopAppRunning(t *testing.T) {
	origDesktopApp := desktopAppRunningFunc
	origLaunchctl := launchctlRunFunc
	t.Cleanup(func() {
		desktopAppRunningFunc = origDesktopApp
		launchctlRunFunc = origLaunchctl
	})

	desktopAppRunningFunc = func() bool { return true }
	launchctlRunFunc = func(args ...string) ([]byte, error) {
		t.Fatalf("launchctl must never be invoked when desktopAppRunningFunc() is true, got args: %v", args)
		return nil, nil
	}

	cmd := newGatewayInstallCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE: %v", err)
	}

	if !strings.Contains(out.String(), "Keylatch.app is already managing keylatchd") {
		t.Errorf("expected refusal message, got: %q", out.String())
	}
}

// TestNewGatewayInstallCmd_MockedLaunchctlNeverInvokesReal verifies the
// launchctlRunFunc seam itself: when desktopAppRunningFunc reports false and
// launchctlRunFunc is mocked to succeed, RunE completes successfully and
// launchctlRunFunc — not the real launchctl binary — is the one invoked with
// "load"/"-w"/<plistPath>. installLaunchdPlist's real filesystem write is
// exercised separately above with an injected plistPath; this test only
// asserts the launchctl call shape, so it stubs installLaunchdPlist-adjacent
// state via the same mocked-runner seam rather than writing to the real
// ~/Library/LaunchAgents path.
func TestNewGatewayInstallCmd_MockedLaunchctlNeverInvokesReal(t *testing.T) {
	origDesktopApp := desktopAppRunningFunc
	origLaunchctl := launchctlRunFunc
	t.Cleanup(func() {
		desktopAppRunningFunc = origDesktopApp
		launchctlRunFunc = origLaunchctl
	})

	desktopAppRunningFunc = func() bool { return false }

	var calls [][]string
	launchctlRunFunc = func(args ...string) ([]byte, error) {
		calls = append(calls, args)
		if len(args) > 0 && args[0] == "list" {
			// Not loaded yet — `launchctl list <label>` exits non-zero.
			return nil, errors.New("exit status 1")
		}
		return []byte("ok"), nil
	}

	// Fake keylatchd on PATH so installLaunchdPlist (invoked internally by
	// RunE against the real launchdPlistPath()) succeeds rather than erroring
	// out before ever reaching the launchctl call.
	binDir := t.TempDir()
	fakeKeylatchd := filepath.Join(binDir, "keylatchd")
	if err := os.WriteFile(fakeKeylatchd, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake keylatchd: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// Redirect HOME so launchdPlistPath() (which resolves against $HOME)
	// never touches the real user's ~/Library/LaunchAgents — t.TempDir()
	// is removed automatically at test end.
	t.Setenv("HOME", t.TempDir())

	cmd := newGatewayInstallCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("launchctlRunFunc: got %d calls, want 2 (list, then load): %v", len(calls), calls)
	}
	if calls[0][0] != "list" {
		t.Errorf("first launchctlRunFunc call: got %v, want [\"list\" <label>]", calls[0])
	}
	if len(calls[1]) < 2 || calls[1][0] != "load" || calls[1][1] != "-w" {
		t.Errorf("second launchctlRunFunc call: got %v, want [\"load\" \"-w\" <plistPath>]", calls[1])
	}
	if !strings.Contains(out.String(), "keylatchd installed and loaded") {
		t.Errorf("expected success message, got: %q", out.String())
	}
}

// TestNewGatewayInstallCmd_SkipsLoadWhenAlreadyLoaded verifies the
// idempotency guard: when `launchctl list <label>` reports the label is
// already loaded (exit 0), RunE must print a "skipping" message and never
// call `launchctl load -w` at all — re-running `gateway install` on an
// already-installed daemon must not risk the "service already loaded" hard
// failure some macOS versions return from `launchctl load`.
func TestNewGatewayInstallCmd_SkipsLoadWhenAlreadyLoaded(t *testing.T) {
	origDesktopApp := desktopAppRunningFunc
	origLaunchctl := launchctlRunFunc
	t.Cleanup(func() {
		desktopAppRunningFunc = origDesktopApp
		launchctlRunFunc = origLaunchctl
	})

	desktopAppRunningFunc = func() bool { return false }

	var calls [][]string
	launchctlRunFunc = func(args ...string) ([]byte, error) {
		calls = append(calls, args)
		if len(args) > 0 && args[0] == "list" {
			// Already loaded — `launchctl list <label>` exits 0.
			return []byte("{ \"PID\" = 1; }"), nil
		}
		t.Fatalf("launchctl load must not be called when already loaded, got args: %v", args)
		return nil, nil
	}

	binDir := t.TempDir()
	fakeKeylatchd := filepath.Join(binDir, "keylatchd")
	if err := os.WriteFile(fakeKeylatchd, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write fake keylatchd: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HOME", t.TempDir())

	cmd := newGatewayInstallCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("RunE: %v", err)
	}

	if len(calls) != 1 || calls[0][0] != "list" {
		t.Fatalf("launchctlRunFunc calls: got %v, want exactly one [\"list\" <label>] call", calls)
	}
	if !strings.Contains(out.String(), "already installed and loaded") {
		t.Errorf("expected already-loaded skip message, got: %q", out.String())
	}
}
