package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cbGatewayInit(t *testing.T) string {
	t.Helper()
	cfgDir := cbIsolate(t)
	_, _, err := cbRun(t, "gateway", "init")
	require.NoError(t, err)
	_, _, err = cbRun(t, "setup", "--headless", "--backend", "file")
	require.NoError(t, err)
	return cfgDir
}

func TestGatewayInit_WritesKeyAndConfigWithPrivatePerms(t *testing.T) {
	cfgDir := cbIsolate(t)

	out, _, err := cbRun(t, "gateway", "init")
	require.NoError(t, err)
	assert.Contains(t, out, "gateway: signing key generated")

	gwDir := filepath.Join(cfgDir, "gateway")
	keyPath := filepath.Join(gwDir, "signing.key")
	cfgPath := filepath.Join(gwDir, "config.json")
	assert.Equal(t, os.FileMode(0o700), cbMode(t, gwDir))
	assert.Equal(t, os.FileMode(0o600), cbMode(t, keyPath))
	assert.Equal(t, os.FileMode(0o600), cbMode(t, cfgPath))

	key, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Len(t, key, 32)

	var cfg map[string]any
	data, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &cfg))
	assert.Equal(t, "127.0.0.1:7878", cfg["bind"])
	assert.Equal(t, "local_process", cfg["mode"])

	out, _, err = cbRun(t, "gateway", "init")
	require.NoError(t, err)
	assert.Contains(t, out, "signing key already exists")
	again, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, key, again, "re-running init must not rotate the signing key")
	_, err = os.Stat(filepath.Join(gwDir, "docker-compose.yml"))
	assert.True(t, os.IsNotExist(err))
}

func TestGatewayInit_DockerWritesCompose(t *testing.T) {
	cfgDir := cbIsolate(t)
	out, _, err := cbRun(t, "gateway", "init", "--docker")
	require.NoError(t, err)
	composePath := filepath.Join(cfgDir, "gateway", "docker-compose.yml")
	assert.Contains(t, out, "docker-compose.yml written to "+composePath)
	data, err := os.ReadFile(composePath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "7878")
}

func TestGatewayInit_GatewayDirIsFile(t *testing.T) {
	cbIsolate(t)
	blocker := filepath.Join(t.TempDir(), "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))
	t.Setenv("KEYLATCH_GATEWAY_DIR", filepath.Join(blocker, "gw"))
	_, _, err := cbRun(t, "gateway", "init")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway init: mkdir")
}

func TestGatewayInit_ConfigWriteFails(t *testing.T) {
	cbIsolate(t)
	t.Setenv("KEYLATCH_GATEWAY_CONFIG", filepath.Join(t.TempDir(), "missing", "config.json"))
	_, _, err := cbRun(t, "gateway", "init")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway init: write config")
}

func TestGatewayToken_CreateListRevoke(t *testing.T) {
	cfgDir := cbGatewayInit(t)

	out, _, err := cbRun(t, "gateway", "token", "create", "ci-bot",
		"--allow", "openrouter.chat", "--allow", "openai.chat", "--ttl", "30m", "--max-uses", "3")
	require.NoError(t, err)
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		k, v, ok := strings.Cut(line, ": ")
		require.True(t, ok, line)
		fields[k] = v
	}
	require.NotEmpty(t, fields["token"])
	require.NotEmpty(t, fields["id"])
	require.NotEmpty(t, fields["accessor"])
	exp, err := time.Parse(time.RFC3339, fields["expires"])
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(30*time.Minute), exp, 2*time.Minute)

	store, err := os.ReadFile(filepath.Join(cfgDir, "gateway-tokens.json"))
	require.NoError(t, err)
	assert.NotContains(t, string(store), fields["token"], "the JWT must never be persisted")

	out, _, err = cbRun(t, "gateway", "token", "list")
	require.NoError(t, err)
	assert.Contains(t, out, "ACCESSOR")
	assert.Contains(t, out, "ci-bot")
	assert.Contains(t, out, "openrouter.chat,openai.chat")
	assert.Contains(t, out, fields["accessor"][:8]+"...")
	assert.NotContains(t, out, fields["token"])

	out, _, err = cbRun(t, "gateway", "token", "list", "--json")
	require.NoError(t, err)
	assert.NotContains(t, out, fields["token"])
	var listed []map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &listed))
	require.Len(t, listed, 1)

	out, _, err = cbRun(t, "gateway", "status")
	require.NoError(t, err)
	assert.Contains(t, out, "gateway: stopped (pid: n/a)")
	assert.Contains(t, out, "active tokens: 1")

	out, _, err = cbRun(t, "gateway", "token", "revoke", fields["id"])
	require.NoError(t, err)
	assert.Contains(t, out, "token "+fields["id"]+" revoked")

	out, _, err = cbRun(t, "gateway", "token", "list")
	require.NoError(t, err)
	assert.NotContains(t, out, "ci-bot")
}

func TestGatewayTokenList_NoCapabilitiesShowsNA(t *testing.T) {
	cbGatewayInit(t)
	_, _, err := cbRun(t, "gateway", "token", "create", "plain", "--max-uses", "1")
	require.NoError(t, err)
	out, _, err := cbRun(t, "gateway", "token", "list")
	require.NoError(t, err)
	assert.Regexp(t, `plain\s+n/a\s+\S+\s+no`, out)
}

func TestGatewayTokenCreate_LLMSessionRules(t *testing.T) {
	cbGatewayInit(t)
	t.Setenv("CLAUDECODE", "1")

	_, _, err := cbRun(t, "gateway", "token", "create", "agent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unlimited")

	_, _, err = cbRun(t, "gateway", "token", "create", "agent", "--max-uses", "2")
	require.NoError(t, err)
	out, _, err := cbRun(t, "gateway", "token", "list")
	require.NoError(t, err)
	assert.Regexp(t, `agent\s+n/a\s+\S+\s+yes`, out)
}

func TestGatewayTokenCreate_Errors(t *testing.T) {
	cbIsolate(t)

	_, _, err := cbRun(t, "gateway", "token", "create", "x", "--ttl", "soon")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid --ttl")

	_, _, err = cbRun(t, "gateway", "token", "create", "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read signing key")

	keyPath := filepath.Join(t.TempDir(), "short.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("short"), 0o600))
	t.Setenv("KEYLATCH_GATEWAY_SIGNING_KEY", keyPath)
	_, _, err = cbRun(t, "gateway", "token", "create", "x", "--ttl", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway token create:")
}

func TestGatewayTokenRevoke_UnknownID(t *testing.T) {
	cbGatewayInit(t)
	_, _, err := cbRun(t, "gateway", "token", "revoke", "does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway token revoke")
}

func TestGatewayTokenList_CorruptStore(t *testing.T) {
	cfgDir := cbIsolate(t)
	require.NoError(t, os.MkdirAll(cfgDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "gateway-tokens.json"), []byte("{not json"), 0o600))
	_, _, err := cbRun(t, "gateway", "token", "list")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway token list")
}

func TestGatewayStatus_RunningFromPIDFile(t *testing.T) {
	cfgDir := cbIsolate(t)
	gwDir := filepath.Join(cfgDir, "gateway")
	require.NoError(t, os.MkdirAll(gwDir, 0o700))
	pid := strconv.Itoa(os.Getpid())
	require.NoError(t, os.WriteFile(filepath.Join(gwDir, "gateway.pid"), []byte(pid+" \n"), 0o600))

	out, _, err := cbRun(t, "gateway", "status")
	require.NoError(t, err)
	assert.Contains(t, out, "gateway: running (pid: "+pid+")")
	assert.Contains(t, out, "active tokens: 0")
}

func TestGatewayDown_NotRunning(t *testing.T) {
	cbIsolate(t)
	out, _, err := cbRun(t, "gateway", "down")
	require.NoError(t, err)
	assert.Contains(t, out, "gateway: not running")
}

func TestGatewayDown_SendsSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals are POSIX-only")
	}
	cfgDir := cbIsolate(t)
	exe, err := os.Executable()
	require.NoError(t, err)
	// gateway down only signals a process whose command name is a keylatch binary.
	named := filepath.Join(t.TempDir(), "keylatchd")
	require.NoError(t, os.Symlink(exe, named))
	child := exec.Command(named)
	child.Env = append(os.Environ(), cbFakeModeEnv+"=sleep")
	require.NoError(t, child.Start())
	waited := make(chan error, 1)
	go func() { waited <- child.Wait() }()
	t.Cleanup(func() {
		_ = child.Process.Kill()
		<-waited
	})

	gwDir := filepath.Join(cfgDir, "gateway")
	require.NoError(t, os.MkdirAll(gwDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(gwDir, "gateway.pid"), []byte(strconv.Itoa(child.Process.Pid)), 0o600))

	out, _, err := cbRun(t, "gateway", "down")
	require.NoError(t, err)
	assert.Contains(t, out, fmt.Sprintf("sent SIGTERM to %d", child.Process.Pid))

	select {
	case werr := <-waited:
		waited <- werr
		var exitErr *exec.ExitError
		require.ErrorAs(t, werr, &exitErr)
		ws, ok := exitErr.Sys().(syscall.WaitStatus)
		require.True(t, ok)
		assert.Equal(t, syscall.SIGTERM, ws.Signal())
	case <-time.After(10 * time.Second):
		t.Fatal("child did not exit after gateway down")
	}
}

func TestGatewayLogs(t *testing.T) {
	cfgDir := cbIsolate(t)
	out, _, err := cbRun(t, "gateway", "logs")
	require.NoError(t, err)
	assert.Contains(t, out, "gateway: no log file found")

	gwDir := filepath.Join(cfgDir, "gateway")
	require.NoError(t, os.MkdirAll(gwDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(gwDir, "gateway.log"), []byte("line one\nline two\n"), 0o600))
	out, _, err = cbRun(t, "gateway", "logs")
	require.NoError(t, err)
	assert.Equal(t, "line one\nline two\n", out)

	t.Setenv("KEYLATCH_GATEWAY_LOG", filepath.Join(gwDir, "gateway.log", "nested"))
	_, _, err = cbRun(t, "gateway", "logs")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway logs: open")
}

func TestGatewayUp_SigningKeyProblems(t *testing.T) {
	cfgDir := cbIsolate(t)
	_, _, err := cbRun(t, "gateway", "up")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read signing key")

	gwDir := filepath.Join(cfgDir, "gateway")
	require.NoError(t, os.MkdirAll(gwDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(gwDir, "signing.key"), []byte("too short"), 0o600))
	_, _, err = cbRun(t, "gateway", "up")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing key must be 32 bytes")
}

func TestGatewayUp_ForegroundBindFailureCleansPID(t *testing.T) {
	cfgDir := cbGatewayInit(t)
	port := cbBusyPort(t)

	out, stderr, err := cbRun(t, "gateway", "up", "--port", strconv.Itoa(port),
		"--budget-per-hour", "5", "--budget-per-day", "50")
	require.Error(t, err, "serving on an occupied port must fail")
	assert.Contains(t, out, fmt.Sprintf("gateway: listening on 127.0.0.1:%d", port))
	assert.NotContains(t, stderr, "audit log")
	_, statErr := os.Stat(filepath.Join(cfgDir, "gateway", "gateway.pid"))
	assert.True(t, os.IsNotExist(statErr), "PID file must be removed when the gateway exits")
}

func TestGatewayUp_RefusesWithoutAuditLog(t *testing.T) {
	cbIsolate(t)
	_, _, err := cbRun(t, "gateway", "init")
	require.NoError(t, err)
	port := cbBusyPort(t)

	_, _, err = cbRun(t, "gateway", "up", "--port", strconv.Itoa(port))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "audit log cannot be opened")
}

func TestGatewayUp_LLMSessionForcesLoopback(t *testing.T) {
	cbGatewayInit(t)
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("KEYLATCH_GATEWAY_LISTEN", "0.0.0.0:9")
	port := cbBusyPort(t)

	out, stderr, err := cbRun(t, "gateway", "up", "--port", strconv.Itoa(port),
		"--unsafe-bind-all", "--listen", "0.0.0.0:1")
	require.Error(t, err)
	assert.Contains(t, stderr, "--unsafe-bind-all ignored")
	assert.Contains(t, stderr, "--listen/KEYLATCH_GATEWAY_LISTEN ignored")
	assert.Contains(t, out, fmt.Sprintf("listening on 127.0.0.1:%d", port))
	assert.NotContains(t, out, "0.0.0.0")
}

func TestGatewayUp_WithProxyUnavailableRollsBack(t *testing.T) {
	cfgDir := cbGatewayInit(t)
	gwPort := cbBusyPort(t)
	proxyPort := freePort(t)

	out, stderr, err := cbRun(t, "gateway", "up", "--port", strconv.Itoa(gwPort),
		"--with-proxy", "--proxy-port", strconv.Itoa(proxyPort))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProxyUnsupported)
	assert.NotContains(t, out, "proxy started")
	assert.Contains(t, stderr, "rolling back gateway")
	_, statErr := os.Stat(filepath.Join(cfgDir, "proxy.pid"))
	assert.True(t, os.IsNotExist(statErr), "an unavailable proxy must not leave a PID file")
}

func TestGatewayUp_WithProxyPortBusyFails(t *testing.T) {
	cbGatewayInit(t)
	gwPort := freePort(t)
	proxyPort := cbBusyPort(t)

	_, stderr, err := cbRun(t, "gateway", "up", "--port", strconv.Itoa(gwPort),
		"--with-proxy", "--proxy-port", strconv.Itoa(proxyPort))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway up --with-proxy")
	assert.Contains(t, stderr, "rolling back gateway")
}

func TestGatewayUp_WithProxyAlreadyRunningSkipsStart(t *testing.T) {
	cfgDir := cbGatewayInit(t)
	gwPort := cbBusyPort(t)
	proxyPort := 18888
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "proxy.pid"), []byte(strconv.Itoa(os.Getpid())), 0o600))
	st, err := json.Marshal(proxyState{PID: os.Getpid(), Port: proxyPort})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(cfgDir, "proxy.state"), st, 0o600))

	out, _, err := cbRun(t, "gateway", "up", "--port", strconv.Itoa(gwPort),
		"--with-proxy", "--proxy-port", strconv.Itoa(proxyPort))
	require.Error(t, err)
	assert.Contains(t, out, "proxy already running on the same port")
	assert.NotContains(t, out, "proxy started")
}

func TestGatewayUp_DetachRelaunchesSelf(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX detach path")
	}
	cfgDir := cbIsolate(t)
	t.Setenv("TMPDIR", t.TempDir())
	argvLog := cbFakeSelf(t, "ok")

	out, _, err := cbRun(t, "gateway", "up", "--detach", "--port", "7979",
		"--unsafe-bind-all", "--listen", "127.0.0.1:7979",
		"--budget-per-hour", "2.5", "--budget-per-day", "10")
	require.NoError(t, err)
	assert.Contains(t, out, "gateway: started in background (pid: 4242)")

	pidData, err := os.ReadFile(filepath.Join(cfgDir, "gateway", "gateway.pid"))
	require.NoError(t, err)
	assert.Equal(t, "4242", strings.TrimSpace(string(pidData)))

	argv := cbReadLog(t, argvLog)
	assert.Contains(t, argv, "gateway up --port=7979 --unsafe-bind-all --listen=127.0.0.1:7979 --budget-per-hour=2.5 --budget-per-day=10")
	assert.NotContains(t, argv, "--detach")
}

func TestGatewayUp_DetachWithoutPIDReportsStarted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX detach path")
	}
	cbIsolate(t)
	t.Setenv("TMPDIR", t.TempDir())
	cbFakeSelf(t, "no-pid")

	out, _, err := cbRun(t, "gateway", "up", "--detach")
	require.NoError(t, err)
	assert.Equal(t, "gateway: started in background\n", out)
}

func TestIsGoRunArtifact(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)

	t.Setenv("TMPDIR", filepath.Dir(exe))
	assert.True(t, isGoRunArtifact(), "binary under TMPDIR looks like a go run artifact")

	t.Setenv("TMPDIR", t.TempDir())
	assert.False(t, isGoRunArtifact())
}
