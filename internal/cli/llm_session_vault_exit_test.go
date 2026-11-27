//go:build experimental

package cli

import (
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
)

// backend vault only exists in experimental builds.
func TestAgentSessionBlocksVaultTrustCommands(t *testing.T) {
	cases := []struct {
		name string
		args []string
		msg  string
	}{
		{"vault init", []string{"backend", "vault", "init", "--addr", "https://vault.invalid", "--transit-key", "k"}, "backend vault init is not permitted"},
		{"vault test", []string{"backend", "vault", "test", "--addr", "https://vault.invalid"}, "backend vault test is not permitted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := cdRunChild(t, true, nil, tc.args...)
			if code != exitcode.SecurityBlock {
				t.Fatalf("exit = %d, want %d (stderr %q)", code, exitcode.SecurityBlock, errOut)
			}
			if !strings.Contains(errOut, tc.msg) {
				t.Fatalf("stderr %q missing %q", errOut, tc.msg)
			}
			if strings.Contains(out, "initialized") || strings.Contains(out, "OK") {
				t.Fatalf("blocked command must not report success: %q", out)
			}
		})
	}
}
