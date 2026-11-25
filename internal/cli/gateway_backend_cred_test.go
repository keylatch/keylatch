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

func TestParseBackendCredentials(t *testing.T) {
	got, err := parseBackendCredentials([]string{"op-sa=OP_SERVICE_ACCOUNT_TOKEN", "bw=BW_SESSION"})
	require.NoError(t, err)
	assert.Equal(t, []backendCredential{{"op-sa", "OP_SERVICE_ACCOUNT_TOKEN"}, {"bw", "BW_SESSION"}}, got)

	for _, bad := range []string{"op-sa", "=BW_SESSION", "../x=BW_SESSION", "a=LD_PRELOAD", "a=PATH", "a=HOME", "kek=BW_SESSION", "a b=BW_SESSION"} {
		_, err := parseBackendCredentials([]string{bad})
		assert.Error(t, err, bad)
	}
	_, err = parseBackendCredentials([]string{"a=BW_SESSION", "a=VAULT_TOKEN"})
	assert.Error(t, err, "repeated name")
	_, err = parseBackendCredentials([]string{"a=BW_SESSION", "b=BW_SESSION"})
	assert.Error(t, err, "repeated variable")
}

func TestExportBackendCredentials_ReadsCredentialDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "op-sa"), []byte(fakeSAToken+"\n"), 0o400))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "doppler"), []byte("dp.st.x"), 0o400))
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "")
	t.Setenv("DOPPLER_TOKEN", "")

	require.NoError(t, exportBackendCredentials([]backendCredential{{"op-sa", "OP_SERVICE_ACCOUNT_TOKEN"}, {"doppler", "DOPPLER_TOKEN"}}))
	assert.Equal(t, fakeSAToken, os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"))
	assert.Equal(t, "dp.st.x", os.Getenv("DOPPLER_TOKEN"))
}

func TestExportBackendCredentials_Refusals(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty"), []byte(" \n"), 0o400))
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv("BW_SESSION", "")

	for _, name := range []string{"missing", "empty"} {
		err := exportBackendCredentials([]backendCredential{{name, "BW_SESSION"}})
		require.Error(t, err, name)
		assert.Empty(t, os.Getenv("BW_SESSION"))
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	err := exportBackendCredentials([]backendCredential{{"x", "BW_SESSION"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CREDENTIALS_DIRECTORY")
}

func TestBackendVerdict_NeverContainsToken(t *testing.T) {
	fakeOPSA(t, 0)
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", fakeSAToken)
	assert.Contains(t, backendVerdict(t.Context(), "OP_SERVICE_ACCOUNT_TOKEN", nil), "authenticated")
	r := fakeOPSA(t, 1)
	v := backendVerdict(t.Context(), "OP_SERVICE_ACCOUNT_TOKEN", nil)
	assert.Contains(t, v, "NOT authenticated")
	assert.NotContains(t, v, fakeSAToken)
	assert.Len(t, r.Calls, 1)
	assert.NotContains(t, backendVerdict(t.Context(), "BW_SESSION", nil), "authenticated")
	assert.Len(t, r.Calls, 1, "no live check for other backends")
}

func TestSystemdInstall_BackendCredentials(t *testing.T) {
	home, binary := systemdTestEnv(t)
	installFakeUserManager(t)
	opCred := filepath.Join(home, "gw", "op-sa.cred")
	dpCred := filepath.Join(home, "gw", "doppler.cred")
	base := []string{"print", "--listen", "10.0.2.2:7878", "--allow-source", "10.0.2.0/24", "--binary", binary}

	out, err := runSystemd(t, append(base, "--backend-credential", "op-sa=OP_SERVICE_ACCOUNT_TOKEN:"+opCred, "--backend-credential", "doppler=DOPPLER_TOKEN:"+dpCred)...)
	require.NoError(t, err)

	assert.Contains(t, out, "LoadCredentialEncrypted=op-sa:"+opCred+"\n")
	assert.Contains(t, out, "LoadCredentialEncrypted=doppler:"+dpCred+"\n")
	assert.Contains(t, out, "LoadCredentialEncrypted=kek:")
	assert.Contains(t, out, "--backend-credential op-sa=OP_SERVICE_ACCOUNT_TOKEN --backend-credential doppler=DOPPLER_TOKEN\n")
	assert.NotContains(t, out, "sh -c")
	assert.NotContains(t, out, "Environment=OP_SERVICE")

	plain, err := runSystemd(t, base...)
	require.NoError(t, err)
	assert.NotContains(t, plain, "backend-credential")
}

func TestSystemdInstall_BackendCredentialRefusals(t *testing.T) {
	_, binary := systemdTestEnv(t)
	installFakeUserManager(t)
	for _, bad := range []string{"op-sa=OP_SERVICE_ACCOUNT_TOKEN", "op-sa=OP_SERVICE_ACCOUNT_TOKEN:op.cred", "op-sa=OP_SERVICE_ACCOUNT_TOKEN:/tmp/a b.cred", "op-sa=OP_SERVICE_ACCOUNT_TOKEN:/tmp/%d.cred", "x=LD_PRELOAD:/tmp/x.cred", "kek=BW_SESSION:/tmp/x.cred"} {
		_, err := runSystemd(t, "print", "--listen", "10.0.2.2:7878", "--allow-source", "10.0.2.0/24", "--binary", binary, "--backend-credential", bad)
		assert.Error(t, err, bad)
	}
}

func TestSystemdInstall_WarnsWhenBackendCredentialMissing(t *testing.T) {
	home, binary := systemdTestEnv(t)
	installFakeUserManager(t)
	out, err := runSystemd(t, "install", "--listen", "10.0.2.2:7878", "--allow-source", "10.0.2.0/24", "--binary", binary, "--backend-credential", "op-sa=OP_SERVICE_ACCOUNT_TOKEN:"+filepath.Join(home, "gw", "op-sa.cred"))
	require.NoError(t, err)
	assert.Contains(t, out, "backend credential op-sa missing")
}

func TestSystemdStatus_CheckBackendDecryptsForOneCallAndHidesToken(t *testing.T) {
	home, binary := systemdTestEnv(t)
	fake := installFakeUserManager(t)
	cred := filepath.Join(home, "gw", "op-sa.cred")
	require.NoError(t, os.MkdirAll(filepath.Dir(cred), 0o700))
	require.NoError(t, os.WriteFile(cred, []byte("sealed"), 0o600))
	_, err := runSystemd(t, "install", "--listen", "10.0.2.2:7878", "--allow-source", "10.0.2.0/24", "--binary", binary, "--backend-credential", "op-sa=OP_SERVICE_ACCOUNT_TOKEN:"+cred)
	require.NoError(t, err)
	fake.outputs["loginctl"] = "yes\n"

	r := fakeOPSA(t, 0)
	r.Responses["/bin/systemd-creds|decrypt|--user|--name=op-sa|"+cred+"|-"] = kexec.MockResponse{Stdout: []byte(fakeSAToken + "\n")}

	out, err := runSystemd(t, "status", "--check-backend")
	require.NoError(t, err)
	assert.Contains(t, out, "backend cred op-sa -> OP_SERVICE_ACCOUNT_TOKEN present")
	assert.Contains(t, out, "backend auth op-sa: service account authenticated")
	assert.NotContains(t, out, fakeSAToken)
	require.Len(t, r.Calls, 2)
	assert.Equal(t, []string{"OP_SERVICE_ACCOUNT_TOKEN=" + fakeSAToken}, r.Calls[1].Env)
	assert.Nil(t, r.Calls[0].Env)
	for _, c := range r.Calls {
		assert.NotContains(t, strings.Join(c.Args, " "), fakeSAToken, "the secret is never an argument")
	}

	plain, err := runSystemd(t, "status")
	require.NoError(t, err)
	assert.Contains(t, plain, "backend cred")
	assert.NotContains(t, plain, "backend auth")
}
