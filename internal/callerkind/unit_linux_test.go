//go:build linux

package callerkind

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeSystemctl(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "systemctl")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	prev := systemctlPaths
	systemctlPaths = []string{path}
	t.Cleanup(func() { systemctlPaths = prev })
}

func TestSystemctlShowReadsUnitProperties(t *testing.T) {
	fakeSystemctl(t, `echo "args:$*" >&2; echo Transient=no; echo FragmentPath=/etc/systemd/system/app.service`)
	info, err := systemctlShow("app.service", false)
	if err != nil || info.Transient || info.FragmentPath != "/etc/systemd/system/app.service" {
		t.Fatalf("info = %+v, err %v", info, err)
	}

	fakeSystemctl(t, `echo Transient=yes`)
	info, err = systemctlShow("run-u1.service", true)
	if err != nil || !info.Transient {
		t.Fatalf("info = %+v, err %v", info, err)
	}
}

func TestSystemctlShowPassesUserFlag(t *testing.T) {
	out := filepath.Join(t.TempDir(), "args")
	fakeSystemctl(t, `echo "$*" >`+out+`; echo Transient=no`)
	if _, err := systemctlShow("app.service", true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(b), "--user show") {
		t.Fatalf("args = %q", b)
	}
}

func TestSystemctlShowFailures(t *testing.T) {
	fakeSystemctl(t, `exit 1`)
	if _, err := systemctlShow("app.service", false); err == nil {
		t.Fatal("a failing systemctl was accepted")
	}
	fakeSystemctl(t, `echo nothing=useful`)
	if _, err := systemctlShow("app.service", false); err == nil {
		t.Fatal("output without Transient was accepted")
	}
	prev := systemctlPaths
	systemctlPaths = []string{filepath.Join(t.TempDir(), "absent")}
	t.Cleanup(func() { systemctlPaths = prev })
	if _, err := systemctlShow("app.service", false); err == nil {
		t.Fatal("missing systemctl was accepted")
	}
}

func TestDetectServiceUnitReadsOwnCgroup(t *testing.T) {
	// The answer depends on where the suite runs; the call must not panic and a
	// reported unit must be a service.
	if unit, ok := detectServiceUnit(); ok && !strings.HasSuffix(unit, ".service") {
		t.Fatalf("unit = %q", unit)
	}
}
