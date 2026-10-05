package trust

import (
	"bytes"
	"testing"
)

// Shared-secret/team hardware paths are unavailable — every
// `shared-secret` subcommand is denied before it runs, regardless of the
// arguments supplied. The underlying presence-proof regression
// (presence_proof_security_test.go, tag securitysuite) documents that
// sharedsecret.Read still accepts an unsigned timestamp as hardware
// presence; that repair requirement is expansion work and intentionally
// stays failing until signed, fresh, replay-resistant proof exists — this
// gate makes the point moot since the CLI never reaches Read.
func TestSecurityRegression_SharedSecretCLIUnavailable(t *testing.T) {
	cases := [][]string{
		{"create", "--name-hmac", "x", "--plaintext-hex", "deadbeef"},
		{"rewrap", "--id", "x", "--member-id", "y"},
		{"rotate", "--id", "x"},
		{"reveal", "--id", "x", "--proof-root", "root"},
	}
	for _, args := range cases {
		root := newSharedSecretCmd()
		var stdout, stderr bytes.Buffer
		root.SetOut(&stdout)
		root.SetErr(&stderr)
		root.SetArgs(args)
		if err := root.Execute(); err == nil {
			t.Errorf("shared-secret %v: expected unavailable error, got nil", args)
		}
	}
}
