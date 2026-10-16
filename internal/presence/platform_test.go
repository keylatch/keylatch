//go:build linux

package presence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakePkcheck(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pkcheck")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPolkitConfirm(t *testing.T) {
	ctx := context.Background()
	start := func(int) (string, error) { return "42", nil }

	t.Run("approved", func(t *testing.T) {
		p := &polkit{pkcheck: fakePkcheck(t, "exit 0"), pid: 1, start: start}
		if err := p.Confirm(ctx, "x", "y"); err != nil {
			t.Fatal(err)
		}
		if p.Name() != "polkit" {
			t.Fatalf("Name = %q", p.Name())
		}
	})
	t.Run("refused", func(t *testing.T) {
		p := &polkit{pkcheck: fakePkcheck(t, "exit 3"), pid: 1, start: start}
		err := p.Confirm(ctx, "x", "y")
		if err == nil || !strings.Contains(err.Error(), "exit 3") || errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("binary cannot run", func(t *testing.T) {
		p := &polkit{pkcheck: filepath.Join(t.TempDir(), "missing"), pid: 1, start: start}
		if err := p.Confirm(ctx, "x", "y"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})
	t.Run("no start time", func(t *testing.T) {
		p := &polkit{pkcheck: fakePkcheck(t, "exit 0"), pid: 1, start: func(int) (string, error) { return "", errors.New("gone") }}
		if err := p.Confirm(ctx, "x", "y"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v, want ErrUnavailable", err)
		}
	})
}

func TestProcStartTimeOfThisProcess(t *testing.T) {
	got, err := procStartTime(os.Getpid())
	if err != nil || got == "" {
		t.Fatalf("procStartTime = %q, %v", got, err)
	}
	if _, err := procStartTime(-1); err == nil {
		t.Fatal("a missing process has a start time")
	}
}

func TestPlatformMethodNeedsBinaryAndPolicy(t *testing.T) {
	dir := t.TempDir()
	bin, policy := filepath.Join(dir, "pkcheck"), filepath.Join(dir, "dev.keylatch.policy")
	for _, f := range []string{bin, policy} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	prevBin, prevPolicy := pkcheckPaths, polkitPolicies
	t.Cleanup(func() { pkcheckPaths, polkitPolicies = prevBin, prevPolicy })

	pkcheckPaths, polkitPolicies = []string{bin}, []string{policy}
	if m := platformMethod(); m == nil {
		t.Fatal("no method although pkcheck and the policy exist")
	}
	pkcheckPaths, polkitPolicies = []string{bin}, []string{filepath.Join(dir, "absent")}
	if m := platformMethod(); m != nil {
		t.Fatal("method offered without the keylatch policy installed")
	}
	pkcheckPaths, polkitPolicies = []string{dir}, []string{policy}
	if m := platformMethod(); m != nil {
		t.Fatal("a directory counted as the pkcheck binary")
	}
}
