package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeSAToken = "ops_canary_service_account_token"

func fakeOPSA(t *testing.T, whoamiExit int) *kexec.MockRunner {
	t.Helper()
	r := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{
		"/bin/op|whoami|--format=json": {ExitCode: whoamiExit},
	}}
	origRunner, origResolve := opSARunner, resolveBinFunc
	opSARunner = r
	resolveBinFunc = func(b string) string { return "/bin/" + b }
	t.Cleanup(func() { opSARunner, resolveBinFunc = origRunner, origResolve })
	t.Setenv("KEYLATCH_OP_BIN", "")
	return r
}

func TestExportOPServiceAccountToken_ReadsCredentialDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "op-sa-token"), []byte(fakeSAToken+"\n"), 0o400))
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv(opServiceAccountEnv, "")

	require.NoError(t, exportOPServiceAccountToken("op-sa-token"))
	assert.Equal(t, fakeSAToken, os.Getenv(opServiceAccountEnv))
}

func TestExportOPServiceAccountToken_Refusals(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty"), []byte(" \n"), 0o400))
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv(opServiceAccountEnv, "")

	for name, want := range map[string]string{"../etc/passwd": "not a path", "/abs/path": "not a path", "missing": "not readable", "empty": "empty"} {
		err := exportOPServiceAccountToken(name)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), want, name)
		assert.Empty(t, os.Getenv(opServiceAccountEnv))
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	err := exportOPServiceAccountToken("op-sa-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CREDENTIALS_DIRECTORY")
}

func TestOPWhoamiVerdict_NeverContainsToken(t *testing.T) {
	r := fakeOPSA(t, 0)
	t.Setenv(opServiceAccountEnv, fakeSAToken)
	assert.Contains(t, opWhoamiVerdict(t.Context(), nil), "authenticated")
	r = fakeOPSA(t, 1)
	v := opWhoamiVerdict(t.Context(), nil)
	assert.Contains(t, v, "NOT authenticated")
	assert.NotContains(t, v, fakeSAToken)
	assert.Len(t, r.Calls, 1)
}

func TestSystemdInstall_OPServiceAccountCredential(t *testing.T) {
	home, binary := systemdTestEnv(t)
	installFakeUserManager(t)
	cred := filepath.Join(home, "gw", "op-sa-token.cred")

	out, err := runSystemd(t, "print", "--listen", "192.168.150.1:8788", "--allow-source", "192.168.150.0/24", "--binary", binary, "--op-service-account-credential", cred)
	require.NoError(t, err)

	assert.Contains(t, out, "LoadCredentialEncrypted=op-sa-token:"+cred+"\n")
	assert.Contains(t, out, "LoadCredentialEncrypted=kek:")
	assert.Contains(t, out, "gateway up --allow-source 192.168.150.0/24 --op-service-account-credential op-sa-token\n")
	// The token name is in the unit; no token value, no env var, no shell wrapper.
	assert.NotContains(t, out, "OP_SERVICE_ACCOUNT_TOKEN")
	assert.NotContains(t, out, "sh -c")

	plain, err := runSystemd(t, "print", "--listen", "192.168.150.1:8788", "--allow-source", "192.168.150.0/24", "--binary", binary)
	require.NoError(t, err)
	assert.NotContains(t, plain, "op-sa-token")
}

func TestSystemdInstall_OPCredentialMustBeSafeAbsolutePath(t *testing.T) {
	_, binary := systemdTestEnv(t)
	installFakeUserManager(t)
	for _, bad := range []string{"op.cred", "/tmp/a b.cred", "/tmp/%d.cred"} {
		_, err := runSystemd(t, "print", "--listen", "192.168.150.1:8788", "--allow-source", "192.168.150.0/24", "--binary", binary, "--op-service-account-credential", bad)
		assert.Error(t, err, bad)
	}
}

func TestSystemdInstall_WarnsWhenOPCredentialMissing(t *testing.T) {
	home, binary := systemdTestEnv(t)
	installFakeUserManager(t)
	out, err := runSystemd(t, "install", "--listen", "192.168.150.1:8788", "--allow-source", "192.168.150.0/24", "--binary", binary, "--op-service-account-credential", filepath.Join(home, "gw", "op-sa-token.cred"))
	require.NoError(t, err)
	assert.Contains(t, out, "1Password service account credential missing")
}

func TestSystemdStatus_CheckOPDecryptsForOneCallAndHidesToken(t *testing.T) {
	home, binary := systemdTestEnv(t)
	fake := installFakeUserManager(t)
	cred := filepath.Join(home, "gw", "op-sa-token.cred")
	require.NoError(t, os.MkdirAll(filepath.Dir(cred), 0o700))
	require.NoError(t, os.WriteFile(cred, []byte("sealed"), 0o600))
	_, err := runSystemd(t, "install", "--listen", "192.168.150.1:8788", "--allow-source", "192.168.150.0/24", "--binary", binary, "--op-service-account-credential", cred)
	require.NoError(t, err)
	fake.outputs["loginctl"] = "yes\n"

	r := fakeOPSA(t, 0)
	r.Responses["/bin/systemd-creds|decrypt|--user|--name=op-sa-token|"+cred+"|-"] = kexec.MockResponse{Stdout: []byte(fakeSAToken + "\n")}

	out, err := runSystemd(t, "status", "--check-op")
	require.NoError(t, err)
	assert.Contains(t, out, "op account   present")
	assert.Contains(t, out, "op auth      service account authenticated")
	assert.NotContains(t, out, fakeSAToken)
	require.Len(t, r.Calls, 2)
	assert.Equal(t, []string{"OP_SERVICE_ACCOUNT_TOKEN=" + fakeSAToken}, r.Calls[1].Env)
	assert.Nil(t, r.Calls[0].Env)
	for _, c := range r.Calls {
		assert.NotContains(t, strings.Join(c.Args, " "), fakeSAToken, "token must never be an argument")
	}

	plain, err := runSystemd(t, "status")
	require.NoError(t, err)
	assert.Contains(t, plain, "op account")
	assert.NotContains(t, plain, "op auth")
}
