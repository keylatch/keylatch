package runner_test

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/localonly"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const appLocalSlug = "app-local-ephemeral-test"

func registerAppLocal(t *testing.T) {
	t.Helper()
	require.NoError(t, registry.Register(registry.ConnectionTemplate{
		Provider:    appLocalSlug,
		DisplayName: "App local",
		Category:    "dev",
		SecretFields: []registry.SecretField{
			{Name: "JWT_SECRET", EnvVar: "JWT_SECRET"},
			{Name: "SESSION_SECRET", EnvVar: "SESSION_SECRET"},
			{Name: "UPSTREAM_KEY", EnvVar: "UPSTREAM_KEY"},
		},
		InjectionRules: []registry.InjectionRule{
			{EnvVar: "JWT_SECRET", Source: "JWT_SECRET"},
			{EnvVar: "SESSION_SECRET", Source: "SESSION_SECRET"},
		},
		AllowedCommandPrefixes: []string{"sh"},
		RuntimeSupport: registry.RuntimeSupport{
			Preferred: registry.RuntimeGatewayTyped,
			Supported: []registry.RuntimeMode{registry.RuntimeGatewayTyped},
		},
	}))
}

type countingBackend struct {
	*mockBackend
	gets  atomic.Int32
	paths []string
}

func (c *countingBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	c.gets.Add(1)
	c.paths = append(c.paths, path)
	return c.mockBackend.Get(ctx, path)
}

func runEnvEcho(t *testing.T, pr runner.ProcessRunner, conn runner.Connection) []string {
	t.Helper()
	var buf strings.Builder
	pr.Stdout = &buf
	_, err := pr.Run(context.Background(), conn,
		[]string{"sh", "-c", `echo "$JWT_SECRET $SESSION_SECRET"`}, runner.RunOptions{})
	require.NoError(t, err)
	return strings.Fields(buf.String())
}

func ephemeralConn() runner.Connection {
	return runner.Connection{
		Name:                   appLocalSlug,
		AllowedCommandPrefixes: []string{"sh"},
		LocalOnly: runner.LocalOnly{
			Class: localonly.ClassDev,
			Fields: map[string]localonly.Mode{
				"JWT_SECRET":     localonly.Ephemeral,
				"SESSION_SECRET": localonly.Ephemeral,
			},
		},
	}
}

func TestProcessRunner_EphemeralPerSessionAndNeverRead(t *testing.T) {
	registerAppLocal(t)
	b := &countingBackend{mockBackend: newMockBackend()}

	first := runEnvEcho(t, runner.ProcessRunner{Backend: b}, ephemeralConn())
	second := runEnvEcho(t, runner.ProcessRunner{Backend: b}, ephemeralConn())

	require.Len(t, first, 2)
	require.Len(t, second, 2)
	assert.NotEqual(t, first[0], first[1], "each field gets its own value")
	assert.NotEqual(t, first[0], second[0], "separate sessions differ")
	assert.NotEqual(t, first[1], second[1], "separate sessions differ")
	assert.Len(t, first[0], 64)
	assert.Zero(t, b.gets.Load(), "the backend must never be read for ephemeral fields")
}

func TestProcessRunner_EphemeralStableWithinSession(t *testing.T) {
	registerAppLocal(t)
	b := &countingBackend{mockBackend: newMockBackend()}
	pr := runner.ProcessRunner{Backend: b, Session: localonly.NewSession()}

	a := runEnvEcho(t, pr, ephemeralConn())
	c := runEnvEcho(t, pr, ephemeralConn())
	assert.Equal(t, a, c, "children of one session share the value")
}

func TestProcessRunner_OnlyEphemeralFieldsSkipRead(t *testing.T) {
	registerAppLocal(t)
	b := &countingBackend{mockBackend: newMockBackend()}
	conn := ephemeralConn()
	delete(conn.LocalOnly.Fields, "SESSION_SECRET")
	path := secretPath("default", "dev", appLocalSlug, "SESSION_SECRET")
	require.NoError(t, b.Set(context.Background(), path, []byte("stored-session"), backend.Meta{Path: path}))

	got := runEnvEcho(t, runner.ProcessRunner{Backend: b}, conn)
	require.Len(t, got, 2)
	// The stored value reaches the child; the output redactor masks it on the way back.
	assert.Equal(t, "[REDACTED]", got[1])
	assert.Equal(t, []string{path}, b.paths)
}

func TestProcessRunner_UnimplementedModesRefused(t *testing.T) {
	registerAppLocal(t)
	for _, m := range []localonly.Mode{localonly.Operation, localonly.Contained} {
		b := &countingBackend{mockBackend: newMockBackend()}
		conn := ephemeralConn()
		conn.LocalOnly.Fields["JWT_SECRET"] = m
		_, err := runner.ProcessRunner{Backend: b}.Run(context.Background(), conn, []string{"sh", "-c", "true"}, runner.RunOptions{})
		require.ErrorIs(t, err, localonly.ErrNotAvailable, string(m))
		assert.Zero(t, b.gets.Load())
	}
}

func TestProcessRunner_ProdEphemeralRefused(t *testing.T) {
	registerAppLocal(t)
	conn := ephemeralConn()
	conn.LocalOnly.Class = localonly.ClassProd
	_, err := runner.ProcessRunner{Backend: newMockBackend()}.Run(context.Background(), conn, []string{"sh", "-c", "true"}, runner.RunOptions{})
	require.ErrorIs(t, err, localonly.ErrEphemeralClass)
}

type captureDriver struct{ env []string }

func (d *captureDriver) Run(_ context.Context, req runner.ExecRequest, _ registry.ConnectionTemplate) (runner.RuntimeReceipt, error) {
	d.env = req.LocalEnv
	return runner.RuntimeReceipt{}, nil
}

func dispatchLocal(t *testing.T, class localonly.Class, mode localonly.Mode, session *localonly.Session) ([]string, error) {
	t.Helper()
	registerAppLocal(t)
	d := &captureDriver{}
	dr := runner.DispatchRunner{Drivers: map[string]runner.Driver{string(registry.RuntimeGatewayTyped): d}}
	_, err := dr.Run(context.Background(), runner.ExecRequest{
		ConnectionSlug: appLocalSlug,
		Runtime:        string(registry.RuntimeGatewayTyped),
		Command:        []string{"sh", "-c", "true"},
		LocalSession:   session,
		LocalOnly: runner.LocalOnly{
			Class:  class,
			Fields: map[string]localonly.Mode{"JWT_SECRET": mode, "SESSION_SECRET": mode},
		},
	})
	return d.env, err
}

func TestDispatch_EphemeralEnvSharedAcrossSession(t *testing.T) {
	s := localonly.NewSession()
	a, err := dispatchLocal(t, localonly.ClassTest, localonly.Ephemeral, s)
	require.NoError(t, err)
	b, err := dispatchLocal(t, localonly.ClassTest, localonly.Ephemeral, s)
	require.NoError(t, err)
	assert.Equal(t, a, b)
	require.Len(t, a, 2)

	c, err := dispatchLocal(t, localonly.ClassTest, localonly.Ephemeral, nil)
	require.NoError(t, err)
	assert.NotEqual(t, a, c)
}

func TestDispatch_RefusesUnsupportedAndProd(t *testing.T) {
	_, err := dispatchLocal(t, localonly.ClassDev, localonly.Contained, nil)
	assert.ErrorIs(t, err, localonly.ErrNotAvailable)
	_, err = dispatchLocal(t, localonly.ClassProd, localonly.Ephemeral, nil)
	assert.ErrorIs(t, err, localonly.ErrEphemeralClass)
}
