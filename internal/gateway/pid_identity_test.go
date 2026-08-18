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

// TestVerifyProcessIdentity_FalsePositive_ArgvSubstring verifies the review
// fix (warn-3): a command whose *argument* contains "keylatch" as a
// substring — but whose executable is unrelated — must NOT match. This is
// the exact false-positive shape the old strings.Contains-on-full-line
// matching was vulnerable to (e.g. an editor opened on a path inside a
// keylatch checkout).
func TestVerifyProcessIdentity_FalsePositive_ArgvSubstring(t *testing.T) {
	cases := []string{
		"vim /repos/keylatch/main.go",
		"grep keylatch /var/log/app.log",
		"/Applications/Visual Studio Code.app/Contents/MacOS/Electron /Users/x/keylatch",
	}
	for _, cmdline := range cases {
		t.Run(cmdline, func(t *testing.T) {
			runner := &kexec.MockRunner{
				Responses: map[string]kexec.MockResponse{
					"/bin/ps|-p|4242|-o|command=": {
						Stdout:   []byte(cmdline + "\n"),
						ExitCode: 0,
					},
				},
			}
			matched, checked := gateway.VerifyProcessIdentity(context.Background(), runner, "/bin/ps", 4242)
			if !checked {
				t.Fatal("VerifyProcessIdentity: expected checked=true")
			}
			if matched {
				t.Errorf("VerifyProcessIdentity: false positive — %q must not match (executable is not keylatch/keylatchd)", cmdline)
			}
		})
	}
}

// TestVerifyProcessIdentity_MatchesBareExecutableName verifies that a
// process invoked by bare name (no directory component) still matches by
// exact basename equality.
func TestVerifyProcessIdentity_MatchesBareExecutableName(t *testing.T) {
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			"/bin/ps|-p|4242|-o|command=": {
				Stdout:   []byte("keylatchd --detach\n"),
				ExitCode: 0,
			},
		},
	}
	matched, checked := gateway.VerifyProcessIdentity(context.Background(), runner, "/bin/ps", 4242)
	if !checked || !matched {
		t.Errorf("VerifyProcessIdentity: expected matched=true, checked=true for bare executable name; got matched=%v checked=%v", matched, checked)
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
