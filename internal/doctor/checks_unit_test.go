package doctor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/config"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxProbe is a scripted kexec.Probe.
type mxProbe struct {
	found      map[string]string
	findErr    map[string]error
	versionErr error
}

func (p *mxProbe) Find(_ context.Context, bin string) (string, bool, error) {
	if err, ok := p.findErr[bin]; ok {
		return "", false, err
	}
	if path, ok := p.found[bin]; ok {
		return path, true, nil
	}
	return "", false, nil
}

func (p *mxProbe) Version(_ context.Context, path string) (string, error) {
	if p.versionErr != nil {
		return "", p.versionErr
	}
	return "v-" + filepath.Base(path), nil
}

func mxDoctorEnv(t *testing.T, extra map[string]string) (string, llmcontext.Lookup) {
	t.Helper()
	dir := t.TempDir()
	return dir, func(k string) string {
		if v, ok := extra[k]; ok {
			return v
		}
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	}
}

func mxWriteConfig(t *testing.T, env llmcontext.Lookup, mutate func(*config.Config)) {
	t.Helper()
	cfg := config.Default()
	mutate(&cfg)
	p := filepath.Join(env("KEYLATCH_CONFIG_DIR"), "config.json")
	require.NoError(t, config.Save(p, cfg))
}

func TestCheckBackendSelected(t *testing.T) {
	_, env := mxDoctorEnv(t, nil)
	st := checkBackendSelected(env)(context.Background())
	assert.True(t, st.OK, "missing config falls back to the default file backend")
	assert.Contains(t, st.Detail, "backend=file")

	mxWriteConfig(t, env, func(c *config.Config) { c.Backend = "carrier-pigeon" })
	st = checkBackendSelected(env)(context.Background())
	assert.False(t, st.OK)
	assert.Contains(t, st.Detail, "not a recognised value")

	mxWriteConfig(t, env, func(c *config.Config) { c.Backend = "keychain" })
	st = checkBackendSelected(env)(context.Background())
	assert.Equal(t, runtime.GOOS == "darwin", st.OK)
}

func TestCheckBackendKeychain_NonDarwinSkips(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("covers the non-macOS branch")
	}
	st := checkBackendKeychain(&mxProbe{})(context.Background())
	assert.True(t, st.OK)
	assert.Contains(t, st.Detail, "skipped")
	st = checkACLKeychainUnlock()(context.Background())
	assert.True(t, st.OK)
	assert.Contains(t, st.Detail, "skipped (not macOS)")
}

func TestCheckBackendOP(t *testing.T) {
	_, env := mxDoctorEnv(t, map[string]string{"KEYLATCH_OP_BIN": "op-custom"})
	st := checkBackendOP(env, &mxProbe{findErr: map[string]error{"op-custom": errors.New("probe broke")}})(context.Background())
	assert.False(t, st.OK)
	assert.Contains(t, st.Detail, "probe broke")

	st = checkBackendOP(env, &mxProbe{})(context.Background())
	assert.True(t, st.OK)
	assert.Contains(t, st.Detail, `bin="op-custom"`)

	st = checkBackendOP(env, &mxProbe{found: map[string]string{"op-custom": "/opt/op-custom"}})(context.Background())
	assert.False(t, st.Warn)
	assert.Contains(t, st.Detail, "backend not selected")

	mxWriteConfig(t, env, func(c *config.Config) { c.Backend = "op" })
	st = checkBackendOP(env, &mxProbe{found: map[string]string{"op-custom": "/opt/op-custom"}})(context.Background())
	assert.True(t, st.Warn)
	assert.Contains(t, st.Detail, "op_bin=/opt/op-custom version=v-op-custom")
}

func TestCheckBackendBW(t *testing.T) {
	_, env := mxDoctorEnv(t, nil)
	st := checkBackendBW(env, &mxProbe{findErr: map[string]error{"bw": errors.New("x")}})(context.Background())
	assert.False(t, st.OK)
	st = checkBackendBW(env, &mxProbe{found: map[string]string{"bw": "/usr/bin/bw"}})(context.Background())
	assert.False(t, st.Warn)
	assert.Contains(t, st.Detail, "backend not selected")
	mxWriteConfig(t, env, func(c *config.Config) { c.Backend = "bw" })
	st = checkBackendBW(env, &mxProbe{found: map[string]string{"bw": "/usr/bin/bw"}})(context.Background())
	assert.True(t, st.Warn)
	assert.Contains(t, st.Detail, "bw_bin=/usr/bin/bw")
}

func TestCheckBackendOPAuth_NeverEchoesToken(t *testing.T) {
	token := "ops_" + strings.Repeat("t", 30)
	_, env := mxDoctorEnv(t, nil)
	st := checkBackendOPAuth(env, &mxProbe{}, &kexec.MockRunner{})(context.Background())
	assert.Contains(t, st.Detail, "skipped (backend != op)")

	mxWriteConfig(t, env, func(c *config.Config) { c.Backend = "op" })
	st = checkBackendOPAuth(env, &mxProbe{}, &kexec.MockRunner{})(context.Background())
	assert.True(t, st.Warn)
	assert.Contains(t, st.Detail, "OP_SERVICE_ACCOUNT_TOKEN not set")

	dir := env("KEYLATCH_CONFIG_DIR")
	withToken := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return dir
		case "OP_SERVICE_ACCOUNT_TOKEN":
			return token
		}
		return ""
	}
	st = checkBackendOPAuth(withToken, &mxProbe{}, &kexec.MockRunner{})(context.Background())
	assert.True(t, st.Warn)
	assert.Contains(t, st.Detail, "op binary not found")

	failing := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{"/usr/bin/op|whoami|--format=json": {ExitCode: 1}}}
	st = checkBackendOPAuth(withToken, &mxProbe{found: map[string]string{"op": "/usr/bin/op"}}, failing)(context.Background())
	assert.False(t, st.OK)
	assert.NotContains(t, st.Detail+st.Fix, token)

	st = checkBackendOPAuth(withToken, &mxProbe{found: map[string]string{"op": "/usr/bin/op"}}, &kexec.MockRunner{})(context.Background())
	assert.False(t, st.Warn)
	assert.Contains(t, st.Detail, "value redacted")
	assert.NotContains(t, st.Detail+st.Fix, token)
}

func TestCheckBackendBWSession_NeverEchoesSession(t *testing.T) {
	session := "bwsess-" + strings.Repeat("s", 30)
	_, env := mxDoctorEnv(t, nil)
	assert.Contains(t, checkBackendBWSession(env, &mxProbe{})(context.Background()).Detail, "skipped (backend != bw)")

	mxWriteConfig(t, env, func(c *config.Config) { c.Backend = "bw" })
	st := checkBackendBWSession(env, &mxProbe{})(context.Background())
	assert.Contains(t, st.Detail, "BW_SESSION not set")

	dir := env("KEYLATCH_CONFIG_DIR")
	withSession := func(k string) string {
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return dir
		case "BW_SESSION":
			return session
		}
		return ""
	}
	st = checkBackendBWSession(withSession, &mxProbe{})(context.Background())
	assert.Contains(t, st.Detail, "bw binary not found")

	st = checkBackendBWSession(withSession, &mxProbe{found: map[string]string{"bw": "/usr/bin/bw"}})(context.Background())
	assert.Contains(t, st.Detail, "value redacted")
	assert.NotContains(t, st.Detail+st.Fix, session)
}

func TestCheckOptionalBackends(t *testing.T) {
	boom := errors.New("boom")
	assert.False(t, checkBackendProtonPass(&mxProbe{findErr: map[string]error{"pass-cli": boom}})(context.Background()).OK)
	assert.Contains(t, checkBackendProtonPass(&mxProbe{found: map[string]string{"pass-cli": "/bin/pass-cli"}})(context.Background()).Detail, "pass-cli found")

	assert.False(t, checkBackendKeeper(&mxProbe{findErr: map[string]error{"keeper": boom}})(context.Background()).OK)
	assert.False(t, checkBackendKeeper(&mxProbe{findErr: map[string]error{"ksm": boom}})(context.Background()).OK)
	assert.Contains(t, checkBackendKeeper(&mxProbe{found: map[string]string{"ksm": "/bin/ksm"}})(context.Background()).Detail, "keeper found: /bin/ksm")
	assert.Contains(t, checkBackendKeeper(&mxProbe{})(context.Background()).Detail, "not found")

	assert.False(t, checkBackendLastPass(&mxProbe{findErr: map[string]error{"lpass": boom}})(context.Background()).OK)
	assert.Contains(t, checkBackendLastPass(&mxProbe{found: map[string]string{"lpass": "/bin/lpass"}})(context.Background()).Detail, "breach history")

	st := checkExternalSOPS(&mxProbe{findErr: map[string]error{"sops": boom}})(context.Background())
	assert.True(t, st.OK && st.Warn, "sops is optional")
	assert.Contains(t, checkExternalSOPS(&mxProbe{found: map[string]string{"sops": "/bin/sops"}})(context.Background()).Detail, "sops_bin=/bin/sops")

	st = checkCosignInstalled(&mxProbe{findErr: map[string]error{"cosign": boom}})(context.Background())
	assert.True(t, st.Warn)
	assert.Contains(t, checkCosignInstalled(&mxProbe{found: map[string]string{"cosign": "/bin/cosign"}})(context.Background()).Detail, "verify --self")
}

func TestCheckExternalDocker(t *testing.T) {
	_, env := mxDoctorEnv(t, nil)
	assert.Contains(t, checkExternalDocker(env, &mxProbe{})(context.Background()).Detail, "skipped")

	mxWriteConfig(t, env, func(c *config.Config) { c.Gateway = &config.GatewayConfig{Mode: "docker"} })
	st := checkExternalDocker(env, &mxProbe{})(context.Background())
	assert.False(t, st.OK)
	assert.Contains(t, st.Detail, "docker binary not found")

	st = checkExternalDocker(env, &mxProbe{findErr: map[string]error{"docker": errors.New("perm")}})(context.Background())
	assert.False(t, st.OK)

	st = checkExternalDocker(env, &mxProbe{found: map[string]string{"docker": "/usr/bin/docker"}})(context.Background())
	assert.True(t, st.OK)
	assert.Contains(t, st.Detail, "docker_bin=/usr/bin/docker")
}

func TestCheckExternalRefs_ScanVaultForSchemes(t *testing.T) {
	dir, env := mxDoctorEnv(t, nil)
	vault := filepath.Join(dir, "vault", "default", "ai", "p")
	require.NoError(t, os.MkdirAll(vault, 0o700))
	// URI-looking content in metadata sidecars must be ignored.
	require.NoError(t, os.WriteFile(filepath.Join(vault, "meta"), []byte("op://not/a/field"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(vault, "fieldmodes"), []byte("op://not/a/field"), 0o600))
	assert.False(t, hasExternalRefConnections(env))
	assert.Contains(t, checkExternalOP(env, &mxProbe{}, &kexec.MockRunner{})(context.Background()).Detail, "skipped")

	require.NoError(t, os.WriteFile(filepath.Join(vault, "api_key"), []byte("op://Vault/Item/field"), 0o600))
	assert.True(t, hasExternalRefConnections(env))

	st := checkExternalOP(env, &mxProbe{findErr: map[string]error{"op": errors.New("x")}}, &kexec.MockRunner{})(context.Background())
	assert.False(t, st.OK)
	st = checkExternalOP(env, &mxProbe{}, &kexec.MockRunner{})(context.Background())
	assert.False(t, st.OK)
	assert.Contains(t, st.Detail, "required for op://")
	signedOut := &kexec.MockRunner{Responses: map[string]kexec.MockResponse{"/bin/op|whoami|--format=json": {ExitCode: 1}}}
	st = checkExternalOP(env, &mxProbe{found: map[string]string{"op": "/bin/op"}}, signedOut)(context.Background())
	assert.True(t, st.OK && st.Warn)
	st = checkExternalOP(env, &mxProbe{found: map[string]string{"op": "/bin/op"}}, &kexec.MockRunner{})(context.Background())
	assert.True(t, st.OK)
	assert.False(t, st.Warn)
}

func TestCheckHookPreToolUse(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	check := checkHookPreToolUse(func(string) string { return "" })

	st := check(context.Background())
	assert.True(t, st.Warn)
	assert.Contains(t, st.Detail, "not found")

	claude := filepath.Join(home, ".claude")
	require.NoError(t, os.MkdirAll(claude, 0o700))
	settings := filepath.Join(claude, "settings.json")

	require.NoError(t, os.WriteFile(settings, []byte("{nope"), 0o600))
	assert.Contains(t, check(context.Background()).Detail, "could not be parsed")

	require.NoError(t, os.WriteFile(settings, []byte(`{"hooks":{}}`), 0o600))
	assert.Contains(t, check(context.Background()).Detail, "keylatch hook not found")

	require.NoError(t, os.WriteFile(settings, []byte(`{"hooks":{"PreToolUse":[{"command":"keylatch hook"}]}}`), 0o600))
	st = check(context.Background())
	assert.False(t, st.Warn)
	assert.Contains(t, st.Detail, "hook detected")

	require.NoError(t, os.Remove(settings))
	require.NoError(t, os.MkdirAll(settings, 0o700))
	assert.Contains(t, check(context.Background()).Detail, "could not read")
}

func TestCheckNoConnections(t *testing.T) {
	dir, env := mxDoctorEnv(t, nil)
	st := checkNoConnections(env)(context.Background())
	assert.True(t, st.OK)
	assert.False(t, st.Warn)
	assert.Contains(t, st.Detail, "no connections configured")

	require.NoError(t, os.MkdirAll(filepath.Join(dir, "vault", "default", "ai", "openai", "meta"), 0o700))
	st = checkNoConnections(env)(context.Background())
	assert.False(t, st.Warn)
	assert.Contains(t, st.Detail, "connections present")
}

func TestCheckGatewayRunning(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "gateway.pid")
	_, env := mxDoctorEnv(t, map[string]string{"KEYLATCH_GATEWAY_PID": pidPath})
	check := checkGatewayRunning(env)

	assert.Contains(t, check(context.Background()).Detail, "gateway.pid not found")

	require.NoError(t, os.WriteFile(pidPath, []byte(" \n"), 0o600))
	assert.Contains(t, check(context.Background()).Detail, "empty gateway.pid")

	require.NoError(t, os.WriteFile(pidPath, []byte("abc"), 0o600))
	assert.Contains(t, check(context.Background()).Detail, "non-numeric")

	require.NoError(t, os.WriteFile(pidPath, []byte(fmt.Sprint(os.Getpid())), 0o600))
	st := check(context.Background())
	assert.False(t, st.Warn)
	assert.Equal(t, fmt.Sprintf("gateway pid=%d", os.Getpid()), st.Detail)

	if runtime.GOOS != "windows" {
		// PIDs near the max are effectively never allocated.
		require.NoError(t, os.WriteFile(pidPath, []byte("4194300"), 0o600))
		st = check(context.Background())
		assert.True(t, st.Warn)
		assert.Contains(t, st.Detail, "stale file")
	}
}

func TestCheckPlaintextRetention(t *testing.T) {
	canary := func(status int, body string) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return strings.TrimPrefix(srv.URL, "http://")
	}
	run := func(addr string) Status {
		return checkPlaintextRetention(func(k string) string {
			if k == "KEYLATCH_UI_ADDR" {
				return addr
			}
			return ""
		})(context.Background())
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	unreachable := ln.Addr().String()
	require.NoError(t, ln.Close())
	st := run(unreachable)
	assert.True(t, st.OK)
	assert.False(t, st.Warn)
	assert.Contains(t, st.Detail, "not running")

	st = run(canary(http.StatusNotFound, ""))
	assert.Contains(t, st.Detail, "not available")

	st = run(canary(http.StatusOK, "not json"))
	assert.Contains(t, st.Detail, "could not parse")

	st = run(canary(http.StatusOK, `{"canary_present":true}`))
	assert.False(t, st.OK, "a retained canary is a hard failure")
	assert.Contains(t, st.Tags, "security")

	st = run(canary(http.StatusOK, `{"canary_present":false}`))
	assert.True(t, st.OK)
	assert.False(t, st.Warn)
	assert.Contains(t, st.Detail, "cleared after run")
}

func TestCheckBootstrapKeyringAndConfig(t *testing.T) {
	dir, env := mxDoctorEnv(t, nil)
	assert.False(t, checkBootstrapKeyring(env)(context.Background()).OK)
	st := checkBootstrapConfig(env)(context.Background())
	assert.False(t, st.OK)
	assert.Contains(t, st.Detail, "not bootstrapped")

	krPath := filepath.Join(dir, "kr", "keyring.json")
	env2 := func(k string) string {
		if k == "KEYLATCH_KEYRING_PATH" {
			return krPath
		}
		return env(k)
	}
	require.NoError(t, os.MkdirAll(filepath.Dir(krPath), 0o700))
	require.NoError(t, os.WriteFile(krPath, nil, 0o600))
	assert.Contains(t, checkBootstrapKeyring(env2)(context.Background()).Detail, "empty")
	require.NoError(t, os.WriteFile(krPath, []byte("{}"), 0o600))
	assert.True(t, checkBootstrapKeyring(env2)(context.Background()).OK)

	cfgPath := filepath.Join(dir, "config.json")
	require.NoError(t, os.WriteFile(cfgPath, []byte("{bad"), 0o600))
	st = checkBootstrapConfig(env)(context.Background())
	assert.False(t, st.OK)
	assert.Contains(t, st.Detail, "not valid JSON")

	mxWriteConfig(t, env, func(c *config.Config) { c.Backend = "op" })
	assert.True(t, checkBootstrapConfig(env)(context.Background()).OK)
	st = checkBootstrapKeyring(env)(context.Background())
	assert.True(t, st.OK)
	assert.Contains(t, st.Detail, "managed by op backend")

	require.NoError(t, os.Remove(cfgPath))
	require.NoError(t, os.MkdirAll(cfgPath, 0o700))
	assert.Contains(t, checkBootstrapConfig(env)(context.Background()).Detail, "could not read")
}

func TestCheckBackendFile(t *testing.T) {
	dir, env := mxDoctorEnv(t, nil)
	assert.Contains(t, checkBackendFile(env)(context.Background()).Detail, "not found")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "vault"), []byte("x"), 0o600))
	assert.Contains(t, checkBackendFile(env)(context.Background()).Detail, "not a directory")
}

func TestSmallHelpers(t *testing.T) {
	assert.Equal(t, "on", boolOnOff(true))
	assert.Equal(t, "off", boolOnOff(false))
	assert.Equal(t, "", redactPathsInString(""))
	assert.Equal(t, "relative/path", redactPathsInString("relative/path"))
	red := redactPathsInString("/home/user/.keylatch")
	assert.True(t, strings.HasPrefix(red, "<redacted:"))
	assert.NotContains(t, red, "home")
	assert.Equal(t, red, redactPathsInString("/home/user/.keylatch"), "redaction is stable")
	assert.NotEmpty(t, version())
}
