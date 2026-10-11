package trust

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
)

const trChildArgsEnv = "TR_TRUST_CMD_CHILD_ARGS"

// TestTrLLMChildProcess runs the CLI in a child process so os.Exit can be observed.
func TestTrLLMChildProcess(t *testing.T) {
	raw := os.Getenv(trChildArgsEnv)
	if raw == "" {
		t.Skip("child helper only")
	}
	args := strings.Split(raw, "\x1f")
	root := trNewRoot()
	if args[0] == "shared-secret" {
		root = trNewSharedSecretRoot()
	}
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		os.Exit(90)
	}
	os.Exit(0)
}

func TestLLMSessionBlocksPrivilegedCommands(t *testing.T) {
	cases := []struct {
		args     []string
		code     int
		stderrIn string
	}{
		{[]string{"trust", "enroll", "secure-enclave"}, exitcode.SecurityBlock, "trust enroll is not permitted in LLM sessions"},
		{[]string{"trust", "enroll", "ssh-agent"}, exitcode.SecurityBlock, "trust enroll is not permitted in LLM sessions"},
		{[]string{"trust", "enroll", "pkcs11"}, exitcode.SecurityBlock, "trust enroll is not permitted in LLM sessions"},
		{[]string{"trust", "enroll", "gpg-card"}, exitcode.SecurityBlock, "trust enroll is not permitted in LLM sessions"},
		{[]string{"trust", "enroll", "fido2"}, exitcode.SecurityBlock, "trust enroll is not permitted in LLM sessions"},
		{[]string{"trust", "challenge"}, exitcode.SecurityBlock, "trust challenge is not permitted in LLM sessions"},
		{[]string{"trust", "approve", "x"}, exitcode.SecurityBlock, "trust approve is not permitted in LLM sessions"},
		{[]string{"trust", "revoke", "x"}, exitcode.SecurityBlock, "trust revoke is not permitted in LLM sessions"},
		{[]string{"trust", "allowlist", "add", "/m.so"}, exitcode.SecurityBlock, "allowlist add is not permitted in LLM sessions"},
		{[]string{"shared-secret", "rewrap"}, 2, "shared-secret rewrap blocked during LLM session"},
		{[]string{"shared-secret", "rotate"}, 2, "shared-secret rotate blocked during LLM session"},
		{[]string{"shared-secret", "reveal", "--proof-root", "r"}, 2, "shared-secret reveal blocked during LLM session"},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			home := t.TempDir()
			cmd := exec.Command(os.Args[0], "-test.run=^TestTrLLMChildProcess$")
			cmd.Env = append(os.Environ(),
				trChildArgsEnv+"="+strings.Join(tc.args, "\x1f"),
				"HOME="+home,
				"CLAUDECODE=1",
			)
			var stderr strings.Builder
			cmd.Stderr = &stderr
			err := cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != tc.code {
				t.Fatalf("exit = %v, want code %d; stderr=%q", err, tc.code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.stderrIn) {
				t.Fatalf("stderr = %q", stderr.String())
			}
			if _, err := os.Stat(filepath.Join(home, ".keylatch")); !os.IsNotExist(err) {
				t.Fatalf("blocked command touched HOME state: %v", err)
			}
		})
	}
}
