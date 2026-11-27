//go:build !windows

package runner_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mxEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *mxEmitter) Emit(_ context.Context, e audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *mxEmitter) actions() []audit.Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]audit.Action, 0, len(m.events))
	for _, e := range m.events {
		out = append(out, e.Action)
	}
	return out
}

func mxKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	_, err := rand.Read(k)
	require.NoError(t, err)
	return k
}

type mxDriverCtor func(srv runner.GatewayServerStarter, key []byte, store string, s runtime.EffectiveSettings, e audit.Emitter) runner.Driver

var mxGatewayDrivers = map[string]mxDriverCtor{
	"typed": runner.NewGatewayTypedDriverWithSettings,
	"sdk":   runner.NewGatewaySDKDriverWithSettings,
}

func mxEnvOf(out string) map[string]string {
	env := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if i := strings.IndexByte(line, '='); i > 0 {
			env[line[:i]] = line[i+1:]
		}
	}
	return env
}

func TestGatewayDrivers_RefuseWhenGatewayDown(t *testing.T) {
	for name, ctor := range mxGatewayDrivers {
		t.Run(name, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "ran")
			d := ctor(&mockGatewayServer{addr: "127.0.0.1:1", running: false}, mxKey(t), filepath.Join(t.TempDir(), "tok.json"), runtime.EffectiveSettings{}, nil)
			rec, err := d.Run(context.Background(), runner.ExecRequest{
				ConnectionSlug: "openai",
				Command:        []string{"touch", marker},
			}, sdkTmpl())
			require.Error(t, err)
			assert.ErrorIs(t, err, runner.ErrGatewayNotRunning)
			var rtErr *runner.RuntimeError
			require.True(t, errors.As(err, &rtErr))
			assert.Equal(t, 5, rtErr.ExitCode)
			assert.Contains(t, err.Error(), "Try: keylatch gateway up")
			assert.Equal(t, "gateway_not_running", rec.PolicyDecision)
			_, statErr := os.Stat(marker)
			assert.True(t, os.IsNotExist(statErr), "subprocess must not run when gateway is down")
		})
	}
}

func TestGatewayDrivers_EmptyCommandAndMintFailure(t *testing.T) {
	for name, ctor := range mxGatewayDrivers {
		t.Run(name, func(t *testing.T) {
			srv := &mockGatewayServer{addr: "127.0.0.1:1", running: true}
			d := ctor(srv, mxKey(t), filepath.Join(t.TempDir(), "tok.json"), runtime.EffectiveSettings{}, nil)
			rec, err := d.Run(context.Background(), runner.ExecRequest{}, sdkTmpl())
			require.Error(t, err)
			assert.Equal(t, "empty_command", rec.PolicyDecision)

			bad := ctor(srv, []byte("short"), filepath.Join(t.TempDir(), "tok.json"), runtime.EffectiveSettings{}, nil)
			rec, err = bad.Run(context.Background(), runner.ExecRequest{Command: []string{"true"}}, sdkTmpl())
			require.Error(t, err)
			assert.Contains(t, err.Error(), "mint token")
			assert.Equal(t, "token_mint_failed", rec.PolicyDecision)
		})
	}
}

func TestGatewayDrivers_ExitCodeAndProcessError(t *testing.T) {
	for name, ctor := range mxGatewayDrivers {
		t.Run(name, func(t *testing.T) {
			srv := &mockGatewayServer{addr: "127.0.0.1:1", running: true}
			d := ctor(srv, mxKey(t), filepath.Join(t.TempDir(), "tok.json"), runtime.EffectiveSettings{}, nil)

			rec, err := d.Run(context.Background(), runner.ExecRequest{
				Command:    []string{"sh", "-c", "exit 7"},
				Capability: "chat",
				Stdout:     &bytes.Buffer{},
				Stderr:     &bytes.Buffer{},
				Stdin:      strings.NewReader(""),
			}, sdkTmpl())
			require.NoError(t, err, "a non-zero child exit is reported in the receipt, not as an error")
			assert.Equal(t, 7, rec.ExitCode)

			rec, err = d.Run(context.Background(), runner.ExecRequest{
				Command: []string{filepath.Join(t.TempDir(), "does-not-exist")},
				Stdout:  &bytes.Buffer{},
				Stderr:  &bytes.Buffer{},
				Stdin:   strings.NewReader(""),
			}, sdkTmpl())
			require.Error(t, err)
			assert.Equal(t, "process_error", rec.PolicyDecision)
		})
	}
}

func TestGatewayDrivers_ChildEnvIsScrubbed(t *testing.T) {
	apiKey := "provider-" + strings.Repeat("x", 20)
	t.Setenv("OPENAI_API_KEY", apiKey)
	t.Setenv("KEYLATCH_VAULT_PATH", "/should/not/leak")
	t.Setenv("MX_KEEP_ME", "kept")

	for name, ctor := range mxGatewayDrivers {
		t.Run(name, func(t *testing.T) {
			wd := t.TempDir()
			emitter := &mxEmitter{}
			d := ctor(&mockGatewayServer{addr: "127.0.0.1:17999", running: true}, mxKey(t), filepath.Join(t.TempDir(), "tok.json"),
				runtime.EffectiveSettings{CanaryInjectionEnabled: true}, emitter)

			var out bytes.Buffer
			rec, err := d.Run(context.Background(), runner.ExecRequest{
				Actor:      "agent-under-test",
				Command:    []string{"sh", "-c", "env; echo PWD_IS=$(pwd -P)"},
				WorkingDir: wd,
				Stdout:     &out,
				Stderr:     &bytes.Buffer{},
				Stdin:      strings.NewReader(""),
			}, sdkTmpl())
			require.NoError(t, err)
			assert.Equal(t, "allowed", rec.PolicyDecision)

			env := mxEnvOf(out.String())
			assert.NotContains(t, out.String(), apiKey, "provider key must never reach the child")
			_, hasVault := env["KEYLATCH_VAULT_PATH"]
			assert.False(t, hasVault, "internal KEYLATCH_* config must be stripped")
			assert.Equal(t, "kept", env["MX_KEEP_ME"])
			assert.NotEmpty(t, env["KEYLATCH_GATEWAY_TOKEN"])
			assert.True(t, strings.HasPrefix(env["KEYLATCH_CANARY_OPENAI"], "klc-canary-openai-"))
			resolvedWD, _ := filepath.EvalSymlinks(wd)
			assert.Equal(t, resolvedWD, env["PWD_IS"])

			require.Equal(t, []audit.Action{audit.ActionCanaryInjected}, emitter.actions())
			emitter.mu.Lock()
			ev := emitter.events[0]
			emitter.mu.Unlock()
			assert.Equal(t, "openai", ev.Extra["provider"])
			assert.NotContains(t, ev.Extra["session_id_hmac"], "agent-under-test", "actor must be hashed")
		})
	}
}

func TestGatewayDrivers_CleanEnvKeepsOnlyRequestedExtras(t *testing.T) {
	t.Setenv("MX_EXTRA_VAR", "extra")
	t.Setenv("MX_DROPPED_VAR", "dropped")
	for name, ctor := range mxGatewayDrivers {
		t.Run(name, func(t *testing.T) {
			d := ctor(&mockGatewayServer{addr: "127.0.0.1:17999", running: true}, mxKey(t), filepath.Join(t.TempDir(), "tok.json"), runtime.EffectiveSettings{}, nil)
			var out bytes.Buffer
			_, err := d.Run(context.Background(), runner.ExecRequest{
				Command:      []string{"env"},
				CleanEnv:     true,
				ExtraEnvVars: []string{"MX_EXTRA_VAR"},
				Stdout:       &out,
				Stderr:       &bytes.Buffer{},
				Stdin:        strings.NewReader(""),
			}, sdkTmpl())
			require.NoError(t, err)
			env := mxEnvOf(out.String())
			assert.Equal(t, "extra", env["MX_EXTRA_VAR"])
			_, dropped := env["MX_DROPPED_VAR"]
			assert.False(t, dropped)
			assert.NotEmpty(t, env["KEYLATCH_RUNTIME"])
		})
	}
}

func TestGatewaySDKDriver_BaseURLVarPerProvider(t *testing.T) {
	cases := map[string]string{
		"anthropic":  "ANTHROPIC_BASE_URL",
		"openrouter": "OPENROUTER_BASE_URL",
		"my-llm":     "MY_LLM_BASE_URL",
	}
	for provider, want := range cases {
		d := runner.NewGatewaySDKDriver(&mockGatewayServer{addr: "127.0.0.1:18001", running: true}, mxKey(t), filepath.Join(t.TempDir(), "tok.json"))
		var out bytes.Buffer
		_, err := d.Run(context.Background(), runner.ExecRequest{
			Command: []string{"env"},
			Stdout:  &out,
			Stderr:  &bytes.Buffer{},
			Stdin:   strings.NewReader(""),
		}, registry.ConnectionTemplate{Provider: provider})
		require.NoError(t, err)
		assert.Equal(t, "http://127.0.0.1:18001", mxEnvOf(out.String())[want], provider)
	}
}

func TestLivenessGuard(t *testing.T) {
	inner := &mxRecordingDriver{}
	guarded := runner.WithLivenessGuard(inner, func() bool { return false }, runner.ErrProxyNotRunning)
	rec, err := guarded.Run(context.Background(), runner.ExecRequest{Runtime: "gateway_proxy"}, registry.ConnectionTemplate{})
	assert.ErrorIs(t, err, runner.ErrProxyNotRunning)
	assert.Equal(t, "not_running", rec.PolicyDecision)
	assert.Equal(t, "gateway_proxy", rec.Runtime)
	assert.Zero(t, inner.calls)

	guarded = runner.WithLivenessGuard(inner, func() bool { return true }, runner.ErrProxyNotRunning)
	rec, err = guarded.Run(context.Background(), runner.ExecRequest{}, registry.ConnectionTemplate{})
	require.NoError(t, err)
	assert.Equal(t, "inner", rec.PolicyDecision)
	assert.Equal(t, 1, inner.calls)
}

type mxRecordingDriver struct{ calls int }

func (d *mxRecordingDriver) Run(context.Context, runner.ExecRequest, registry.ConnectionTemplate) (runner.RuntimeReceipt, error) {
	d.calls++
	return runner.RuntimeReceipt{PolicyDecision: "inner"}, nil
}
