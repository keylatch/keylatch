package doctor_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// checks_op_auth_test.go covers the fix for backend.op.auth and
// external.op: both previously reported OK whenever OP_SERVICE_ACCOUNT_TOKEN
// was merely non-empty, without ever actually running `op whoami` to confirm
// the token authenticates. A revoked/expired token reported a false OK. The
// key regression case in each pair below is the "token set but whoami
// fails" scenario — that is exactly the state the old code could not catch.

func opWhoamiKey(bin string) string {
	return bin + "|whoami|--format=json"
}

// --- backend.op.auth ---

func TestCheckBackendOPAuth_TokenValid_WhoamiSucceeds_OK(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "op")
	env = makeEnv(map[string]string{
		"KEYLATCH_CONFIG_DIR":      env("KEYLATCH_CONFIG_DIR"),
		"OP_SERVICE_ACCOUNT_TOKEN": "ops_fake_token_value",
		"KEYLATCH_OP_BIN":          "/usr/local/bin/op",
	})

	probe := newMockProbe()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			opWhoamiKey("/usr/local/bin/op"): {ExitCode: 0},
		},
	}

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe, Runner: runner})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.op.auth")
	assert.True(t, s.OK)
	assert.False(t, s.Warn)
	assert.Contains(t, s.Detail, "verified via `op whoami`")
}

// TestCheckBackendOPAuth_TokenSet_WhoamiFails_NotOK is the regression test:
// the old implementation never ran `op whoami` at all, so a revoked/expired
// token still reported OK. This must now report OK=false.
func TestCheckBackendOPAuth_TokenSet_WhoamiFails_NotOK(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "op")
	env = makeEnv(map[string]string{
		"KEYLATCH_CONFIG_DIR":      env("KEYLATCH_CONFIG_DIR"),
		"OP_SERVICE_ACCOUNT_TOKEN": "ops_revoked_token_value",
		"KEYLATCH_OP_BIN":          "/usr/local/bin/op",
	})

	probe := newMockProbe()
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			opWhoamiKey("/usr/local/bin/op"): {ExitCode: 1, Stderr: []byte("[ERROR] 401: You are not currently signed in")},
		},
	}

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe, Runner: runner})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.op.auth")
	assert.False(t, s.OK, "a revoked/expired token must not report OK")
	assert.Contains(t, s.Detail, "op whoami` failed")
	assert.NotEmpty(t, s.Fix)
}

func TestCheckBackendOPAuth_NoToken_WarnsWithoutExec(t *testing.T) {
	_, env := bootstrappedHome(t)
	selectBackend(t, env, "op")

	probe := newMockProbe()
	runner := &kexec.MockRunner{} // no responses registered — a call would return zeroed values, not an error

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe, Runner: runner})
	require.NoError(t, err)

	s := findCheck(t, report, "backend.op.auth")
	assert.True(t, s.OK)
	assert.True(t, s.Warn)
	assert.Empty(t, runner.Calls, "must not attempt op whoami when no token is set")
}

// --- external.op ---

// writeExternalOPRef writes a vault field file containing an op:// reference
// so hasExternalRefConnections(env) returns true, activating the "external"
// category checks.
func writeExternalOPRef(t *testing.T, env func(string) string) {
	t.Helper()
	vaultDir := paths.Vault(env)
	require.NoError(t, os.MkdirAll(vaultDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(vaultDir, "some-field"), []byte("op://vault/item/field"), 0o600))
}

func TestCheckExternalOP_SignedIn_OK(t *testing.T) {
	_, env := bootstrappedHome(t)
	writeExternalOPRef(t, env)

	probe := newMockProbe()
	probe.found["op"] = "/usr/local/bin/op"
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			opWhoamiKey("/usr/local/bin/op"): {ExitCode: 0},
		},
	}

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe, Runner: runner})
	require.NoError(t, err)

	s := findCheck(t, report, "external.op")
	assert.True(t, s.OK)
	assert.False(t, s.Warn)
	assert.Contains(t, s.Detail, "signed in")
}

// TestCheckExternalOP_NotSignedIn_Warns is the regression test: the old
// implementation called `op --version` (always succeeds when the binary
// exists) instead of `op whoami`, so a signed-out CLI never triggered a
// warning. This must now warn.
func TestCheckExternalOP_NotSignedIn_Warns(t *testing.T) {
	_, env := bootstrappedHome(t)
	writeExternalOPRef(t, env)

	probe := newMockProbe()
	probe.found["op"] = "/usr/local/bin/op"
	runner := &kexec.MockRunner{
		Responses: map[string]kexec.MockResponse{
			opWhoamiKey("/usr/local/bin/op"): {ExitCode: 1, Stderr: []byte("[ERROR] 401: You are not currently signed in")},
		},
	}

	report, err := doctor.Run(context.Background(), doctor.Options{Verbose: true, Env: env, Probe: probe, Runner: runner})
	require.NoError(t, err)

	s := findCheck(t, report, "external.op")
	assert.True(t, s.OK, "warn, not hard-fail, per the documented graceful-degrade policy")
	assert.True(t, s.Warn, "a signed-out op CLI must warn — the previous `op --version` check could never catch this")
	assert.Contains(t, s.Detail, "not signed in")
}
