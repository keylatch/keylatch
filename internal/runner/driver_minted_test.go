package runner_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubMinted is a credential that records whether it was revoked.
type stubMinted struct {
	mu     sync.Mutex
	value  string
	err    error
	closed int
}

func (s *stubMinted) Value(context.Context, string) ([]byte, error) {
	return []byte(s.value), s.err
}

func (s *stubMinted) Close() {
	s.mu.Lock()
	s.closed++
	s.mu.Unlock()
}

// stubOpener hands out cred and records what it was asked for.
type stubOpener struct {
	cred  *stubMinted
	err   error
	calls []runner.MintOpenRequest
}

func (o *stubOpener) open(_ context.Context, _ registry.ConnectionTemplate, req runner.MintOpenRequest) (runner.MintedCredential, error) {
	o.calls = append(o.calls, req)
	if o.err != nil {
		return nil, o.err
	}
	return o.cred, nil
}

func mintedTmpl(provider string) registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: provider,
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeMinted,
			Supported: []registry.RuntimeMode{registry.RuntimeMinted},
		},
		MintedFields: []string{"token"},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "TEST_API_KEY", Source: "token"},
		},
	}
}

func staticTmpl() registry.ConnectionTemplate {
	return registry.ConnectionTemplate{
		Provider: "static",
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeMinted,
			Supported: []registry.RuntimeMode{registry.RuntimeMinted},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "TEST_API_KEY", Source: "api_key"},
		},
	}
}

func runMinted(t *testing.T, o *stubOpener, req runner.ExecRequest, tmpl registry.ConnectionTemplate) (string, runner.RuntimeReceipt, error) {
	t.Helper()
	var out strings.Builder
	req.Stdout, req.Stderr = &out, &strings.Builder{}
	receipt, err := runner.NewMintedDriver(o.open).Run(context.Background(), req, tmpl)
	return out.String(), receipt, err
}

func TestMintedUsesNamespace(t *testing.T) {
	for _, tc := range []struct{ given, want string }{{"", "default"}, {"team-a", "team-a"}} {
		o := &stubOpener{cred: &stubMinted{value: "minted-value"}}
		_, _, err := runMinted(t, o, runner.ExecRequest{
			ConnectionSlug: "myapi", Namespace: tc.given, Command: []string{"sh", "-c", "true"},
		}, mintedTmpl("myapi"))
		require.NoError(t, err)
		require.Len(t, o.calls, 1)
		assert.Equal(t, tc.want, o.calls[0].Namespace)
		assert.Equal(t, "myapi", o.calls[0].Connection)
	}
}

func TestMintedRefusesStatic(t *testing.T) {
	o := &stubOpener{cred: &stubMinted{value: "never"}}
	_, _, err := runMinted(t, o, runner.ExecRequest{
		ConnectionSlug: "static", Command: []string{"sh", "-c", "true"},
	}, staticTmpl())
	require.Error(t, err)
	assert.True(t, errors.Is(err, runner.ErrUnsupportedRuntime))
	assert.Empty(t, o.calls, "a template with only static fields never opens a credential")

	_, _, err = runMinted(t, o, runner.ExecRequest{
		ConnectionSlug: "static", Command: []string{"sh", "-c", "true"},
	}, func() registry.ConnectionTemplate {
		tm := mintedTmpl("static")
		tm.RuntimeSupport = registry.RuntimeSupport{Preferred: registry.RuntimeGatewayTyped, Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped}}
		return tm
	}())
	assert.True(t, errors.Is(err, runner.ErrUnsupportedRuntime), "a template that does not list minted is refused")
}

func TestMintedEnvAllowlist(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "parent-secret-value")
	t.Setenv("KEYLATCH_DATA_DIR", "/should/not/leak")
	t.Setenv("TEST_API_KEY", "parent-shadowed-value")
	o := &stubOpener{cred: &stubMinted{value: "minted-scoped-value"}}
	out, receipt, err := runMinted(t, o, runner.ExecRequest{
		ConnectionSlug: "myapi", Command: []string{"sh", "-c", "env"},
	}, mintedTmpl("myapi"))
	require.NoError(t, err)
	assert.Contains(t, out, "TEST_API_KEY=")
	assert.NotContains(t, out, "parent-secret-value")
	assert.NotContains(t, out, "parent-shadowed-value")
	assert.NotContains(t, out, "KEYLATCH_DATA_DIR")
	assert.Contains(t, out, "KEYLATCH_RUNTIME=minted")
	assert.NotContains(t, out, "minted-scoped-value", "the output guard masks the minted value")
	assert.Equal(t, "minted", receipt.Runtime)
}

func TestMintedInjectsTheMintedValue(t *testing.T) {
	o := &stubOpener{cred: &stubMinted{value: "scoped-token-abc123xyz"}}
	out, _, err := runMinted(t, o, runner.ExecRequest{
		ConnectionSlug: "myapi", Command: []string{"sh", "-c", `test "$TEST_API_KEY" = scoped-token-abc123xyz && echo equal`},
	}, mintedTmpl("myapi"))
	require.NoError(t, err)
	assert.Equal(t, "equal\n", out)
}

func TestMintedKeepsInjectedVariableUnderCleanEnv(t *testing.T) {
	o := &stubOpener{cred: &stubMinted{value: "scoped-token-abc123xyz"}}
	_, receipt, err := runMinted(t, o, runner.ExecRequest{
		ConnectionSlug: "myapi", CleanEnv: true,
		Command: []string{"sh", "-c", `test "$TEST_API_KEY" = scoped-token-abc123xyz`},
	}, mintedTmpl("myapi"))
	require.NoError(t, err)
	assert.Zero(t, receipt.ExitCode)
}

func TestMintedRevokesOnExit(t *testing.T) {
	for name, script := range map[string]string{"success": "true", "failure": "exit 3"} {
		t.Run(name, func(t *testing.T) {
			cred := &stubMinted{value: "minted-value"}
			_, receipt, err := runMinted(t, &stubOpener{cred: cred}, runner.ExecRequest{
				ConnectionSlug: "myapi", Command: []string{"sh", "-c", script},
			}, mintedTmpl("myapi"))
			require.NoError(t, err)
			assert.Equal(t, 1, cred.closed, "the credential is revoked once the command exits")
			if name == "failure" {
				assert.Equal(t, 3, receipt.ExitCode)
			}
		})
	}
}

func TestMintedRevokesWhenTheValueCannotBeMinted(t *testing.T) {
	cred := &stubMinted{err: errors.New("provider refused")}
	_, _, err := runMinted(t, &stubOpener{cred: cred}, runner.ExecRequest{
		ConnectionSlug: "myapi", Command: []string{"sh", "-c", "true"},
	}, mintedTmpl("myapi"))
	require.Error(t, err)
	assert.Equal(t, 1, cred.closed)
}

func TestMintedPolicyRefusalPropagates(t *testing.T) {
	o := &stubOpener{err: errors.New("mint denied by policy")}
	_, _, err := runMinted(t, o, runner.ExecRequest{
		ConnectionSlug: "myapi", Command: []string{"sh", "-c", "true"},
	}, mintedTmpl("myapi"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mint denied by policy")
}

func TestMintedEmptyCommand(t *testing.T) {
	_, _, err := runMinted(t, &stubOpener{cred: &stubMinted{}}, runner.ExecRequest{ConnectionSlug: "myapi"}, mintedTmpl("myapi"))
	require.Error(t, err)
}
