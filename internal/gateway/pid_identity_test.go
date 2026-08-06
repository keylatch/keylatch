package gateway_test

import (
	"context"
	"errors"
	"testing"

	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/gateway"
)

// TestVerifyProcessIdentity_Match verifies that a `ps` output naming the
// keylatch daemon is reported as a matched, checked identity (L2).
func TestVerifyProcessIdentity_Match(t *testing.T) {
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/ps|-p|4242|-o|command=": {
				Stdout:   []byte("/usr/local/bin/keylatchd --detach\n"),
				ExitCode: 0,
			},
		},
	}

	matched, checked := gateway.VerifyProcessIdentity(context.Background(), runner, "/bin/ps", 4242)
	if !checked {
		t.Fatal("VerifyProcessIdentity: expected checked=true")
	}
	if !matched {
		t.Error("VerifyProcessIdentity: expected matched=true for keylatchd command line")
	}
}

// TestVerifyProcessIdentity_Mismatch verifies that a `ps` output naming an
// unrelated process is reported as checked but not matched (L2) — this is
// the stale-PID case gateway up --force must recover from.
func TestVerifyProcessIdentity_Mismatch(t *testing.T) {
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/ps|-p|4242|-o|command=": {
				Stdout:   []byte("/usr/bin/some-unrelated-daemon\n"),
				ExitCode: 0,
			},
		},
	}

	matched, checked := gateway.VerifyProcessIdentity(context.Background(), runner, "/bin/ps", 4242)
	if !checked {
		t.Fatal("VerifyProcessIdentity: expected checked=true")
	}
	if matched {
		t.Error("VerifyProcessIdentity: expected matched=false for unrelated command line")
	}
}

// TestVerifyProcessIdentity_ExecError verifies that a runner error surfaces
// as checked=false, so callers know verification could not be performed.
func TestVerifyProcessIdentity_ExecError(t *testing.T) {
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/ps|-p|4242|-o|command=": {
				Err: errors.New("exec: ps not found"),
			},
		},
	}

	matched, checked := gateway.VerifyProcessIdentity(context.Background(), runner, "/bin/ps", 4242)
	if checked {
		t.Error("VerifyProcessIdentity: expected checked=false on runner error")
	}
	if matched {
		t.Error("VerifyProcessIdentity: matched must be false when checked is false")
	}
}

// TestVerifyProcessIdentity_NonZeroExit verifies that a non-zero ps exit
// code (e.g. "no such pid") is treated as unchecked, not as a mismatch.
func TestVerifyProcessIdentity_NonZeroExit(t *testing.T) {
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/ps|-p|4242|-o|command=": {
				Stderr:   []byte("ps: 4242: No such process\n"),
				ExitCode: 1,
			},
		},
	}

	matched, checked := gateway.VerifyProcessIdentity(context.Background(), runner, "/bin/ps", 4242)
	if checked {
		t.Error("VerifyProcessIdentity: expected checked=false on non-zero exit")
	}
	if matched {
		t.Error("VerifyProcessIdentity: matched must be false when checked is false")
	}
}

// TestVerifyProcessIdentity_EmptyOutput verifies that empty ps output is
// treated as unchecked rather than a confident mismatch.
func TestVerifyProcessIdentity_EmptyOutput(t *testing.T) {
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/ps|-p|4242|-o|command=": {
				Stdout:   []byte(""),
				ExitCode: 0,
			},
		},
	}

	matched, checked := gateway.VerifyProcessIdentity(context.Background(), runner, "/bin/ps", 4242)
	if checked {
		t.Error("VerifyProcessIdentity: expected checked=false on empty output")
	}
	if matched {
		t.Error("VerifyProcessIdentity: matched must be false when checked is false")
	}
}

// TestVerifyProcessIdentity_NilInputs verifies the guard-clause paths never
// panic and always report checked=false.
func TestVerifyProcessIdentity_NilInputs(t *testing.T) {
	if matched, checked := gateway.VerifyProcessIdentity(context.Background(), nil, "/bin/ps", 4242); checked || matched {
		t.Error("VerifyProcessIdentity: nil runner must yield checked=false, matched=false")
	}
	runner := &kexec.MockRunner{}
	if matched, checked := gateway.VerifyProcessIdentity(context.Background(), runner, "", 4242); checked || matched {
		t.Error("VerifyProcessIdentity: empty psBin must yield checked=false, matched=false")
	}
	if matched, checked := gateway.VerifyProcessIdentity(context.Background(), runner, "/bin/ps", 0); checked || matched {
		t.Error("VerifyProcessIdentity: pid<=0 must yield checked=false, matched=false")
	}
}
