//go:build !windows

package control

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/adapter"
	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/placeholder"
	"github.com/keylatch/keylatch/internal/policy/enforce"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runner"
)

const dbPassword = "stored-database-password-0123456789"

// trustDB is a database that accepts any login and reports the startup
// parameters it received.
func trustDB(users chan<- string) func(context.Context, string, string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) {
		near, far := net.Pipe()
		go func() {
			defer func() { _ = far.Close() }()
			var head [8]byte
			if _, err := io.ReadFull(far, head[:]); err != nil {
				return
			}
			body := make([]byte, binary.BigEndian.Uint32(head[:4])-8)
			if _, err := io.ReadFull(far, body); err != nil {
				return
			}
			users <- string(body)
			_, _ = far.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0, 'Z', 0, 0, 0, 5, 'I'})
			_, _ = io.Copy(far, far)
		}()
		return near, nil
	}
}

func adapterWorld(t *testing.T, users chan<- string) *containedWorld {
	t.Helper()
	w := newContainedWorld(t)
	mgr, err := adapter.NewManager(adapter.Config{
		Resolver: fixedResolver{"db_password": dbPassword}, Audit: w.audit, PlainUpstream: true,
		Upstream: placeholder.Upstream{Dial: trustDB(users)},
	})
	require.NoError(t, err)
	t.Cleanup(mgr.Close)
	w.srv.cfg.Adapters = mgr
	return w
}

func adapterRequest() *RunRequest {
	return &RunRequest{Connection: "supabase", Tier: TierAdapter, Target: "db.abc.supabase.co:5432", DBUser: "app_owner", Database: "prod", Command: []string{"psql"}}
}

func session(t *testing.T, w *containedWorld, rr *RunRequest) Response {
	t.Helper()
	conn := w.connect(context.Background())
	require.NoError(t, writeFrame(conn, Request{Op: OpRunSession, Run: rr}))
	var resp Response
	require.NoError(t, readFrame(bufio.NewReader(conn), &resp, maxFrame))
	return resp
}

func TestPostgresAdapterSessionKeepsThePasswordOutOfTheChild(t *testing.T) {
	users := make(chan string, 2)
	w := adapterWorld(t, users)

	resp := session(t, w, adapterRequest())
	require.True(t, resp.OK, resp.Error)
	require.NotNil(t, resp.Session)
	assert.Equal(t, TierAdapter, resp.Session.Tier)
	assert.Equal(t, "adapter", resp.Session.Runtime)
	assert.NotEmpty(t, resp.Session.ProxyID)

	env := map[string]string{}
	for _, e := range resp.Session.Env.Set {
		env[e.Name] = e.Value
	}
	assert.Equal(t, "app_owner", env["PGUSER"])
	assert.True(t, strings.HasPrefix(env["PGPASSWORD"], adapter.TokenPrefix), "the child's password is the session token")
	assert.Contains(t, env["DATABASE_URL"], env["PGPASSWORD"])
	assert.Contains(t, env["DATABASE_URL"], "/prod?sslmode=disable")
	assert.Contains(t, resp.Session.Env.Strip, "SUPABASE_DB_PASSWORD", "the template's own variable for the password is cleared")
	raw, _ := json.Marshal(resp)
	assert.NotContains(t, string(raw), dbPassword)

	// The policy engine was asked about the adapter runtime and tier.
	require.NotEmpty(t, w.decided)
	assert.Equal(t, "adapter", w.decided[0].Runtime)
	assert.Equal(t, "D4", w.decided[0].Tier)
	decided := w.events(audit.ActionRunDecided)
	require.Len(t, decided, 1)
	assert.Equal(t, "D4", decided[0].Extra["tier"])
	assert.Equal(t, []string{"db.abc.supabase.co:5432"}, decided[0].Extra["hosts"])

	// Connecting through the session with the token reaches the database as the role.
	conn := w.connect(context.Background())
	r := bufio.NewReader(conn)
	require.NoError(t, writeFrame(conn, Request{Op: OpProxy, Proxy: resp.Session.ProxyID, RunID: resp.Session.RunID}))
	var ok Response
	require.NoError(t, readFrame(r, &ok, maxFrame))
	require.True(t, ok.OK, ok.Error)

	startup := []byte("user\x00whoever\x00database\x00\x00\x00")
	pkt := make([]byte, 8, 8+len(startup))
	binary.BigEndian.PutUint32(pkt, uint32(8+len(startup)))
	binary.BigEndian.PutUint32(pkt[4:], 196608)
	_, err := conn.Write(append(pkt, startup...))
	require.NoError(t, err)
	head := make([]byte, 9)
	_, err = io.ReadFull(r, head)
	require.NoError(t, err)
	assert.Equal(t, byte('R'), head[0])
	pw := append([]byte(env["PGPASSWORD"]), 0)
	msg := append([]byte{'p', 0, 0, 0, byte(4 + len(pw))}, pw...)
	_, err = conn.Write(msg)
	require.NoError(t, err)
	select {
	case got := <-users:
		assert.Contains(t, got, "user\x00app_owner\x00")
		assert.Contains(t, got, "database\x00prod\x00", "the default database applies when the client names none")
	case <-time.After(5 * time.Second):
		t.Fatal("the database never saw a login")
	}

	// Ending the session revokes it.
	end := w.connect(context.Background())
	require.NoError(t, writeFrame(end, Request{Op: OpEndSession, Proxy: resp.Session.ProxyID}))
	var ended Response
	require.NoError(t, readFrame(bufio.NewReader(end), &ended, maxFrame))
	assert.True(t, ended.OK)
	again := w.connect(context.Background())
	require.NoError(t, writeFrame(again, Request{Op: OpProxy, Proxy: resp.Session.ProxyID}))
	var gone Response
	require.NoError(t, readFrame(bufio.NewReader(again), &gone, maxFrame))
	assert.Equal(t, CodeNotFound, gone.Code)
}

func TestAdapterSessionRefusals(t *testing.T) {
	w := adapterWorld(t, make(chan string, 1))

	t.Run("a database outside the adapter hosts", func(t *testing.T) {
		rr := adapterRequest()
		rr.Target = "evil.example.com:5432"
		resp := session(t, w, rr)
		assert.False(t, resp.OK)
		assert.Equal(t, CodeRefused, resp.Code)
		assert.Contains(t, resp.Error, "--target")
	})

	t.Run("a connection without an adapter", func(t *testing.T) {
		rr := adapterRequest()
		rr.Connection = "stripe"
		resp := session(t, w, rr)
		assert.False(t, resp.OK)
		assert.Contains(t, resp.Error, "no protocol adapter")
	})

	t.Run("an unknown connection", func(t *testing.T) {
		rr := adapterRequest()
		rr.Connection = "nonexistent"
		assert.Equal(t, CodeNotFound, session(t, w, rr).Code)
	})

	t.Run("another runtime", func(t *testing.T) {
		rr := adapterRequest()
		rr.Runtime = "contained"
		assert.False(t, session(t, w, rr).OK)
	})

	t.Run("policy denies", func(t *testing.T) {
		w.decide = func(enforce.Request) enforce.Decision { return enforce.Decision{Reason: "no databases"} }
		resp := session(t, w, adapterRequest())
		assert.False(t, resp.OK)
		assert.Contains(t, resp.Error, "policy denies D4")
	})
}

func TestRunArgsCarryTheDatabaseSelection(t *testing.T) {
	ra, err := parseRunArgs([]string{"--tier", "d4", "--target", "db.abc.supabase.co:5432", "--db-user=app_owner", "--database", "prod", "supabase", "--", "psql"})
	require.NoError(t, err)
	assert.Equal(t, TierAdapter, ra.tier)
	assert.Equal(t, "db.abc.supabase.co:5432", ra.target)
	assert.Equal(t, "app_owner", ra.dbUser)
	assert.Equal(t, "prod", ra.database)
	_, err = parseRunArgs([]string{"--target"})
	assert.Error(t, err)
}

func TestAdapterTierIsUnavailableWithoutAManager(t *testing.T) {
	w := newContainedWorld(t)
	resp := session(t, w, adapterRequest())
	assert.False(t, resp.OK)
	assert.Equal(t, CodeUnavailable, resp.Code)
}

func TestAdapterSessionNeedsAnApprovalFromAgents(t *testing.T) {
	w := adapterWorld(t, make(chan string, 1))
	w.decide = func(enforce.Request) enforce.Decision { return enforce.Decision{Allow: true, Approval: "ask"} }
	w.approve = func(ApprovalRequest) (string, error) { return "", io.ErrClosedPipe }
	resp := session(t, w, adapterRequest())
	assert.False(t, resp.OK)
	assert.Contains(t, resp.Error, "approval refused")
}

func registryTemplate() registry.ConnectionTemplate {
	hosts := []string{"registry.test.example:443"}
	return registry.ConnectionTemplate{
		Provider: "regtest", DisplayName: "Registry test",
		SecretFields:     []registry.SecretField{{Name: "token", Required: true, Sensitive: true}},
		Hosts:            hosts,
		Slots:            []registry.Slot{{Field: "token", In: registry.SlotBasic, Part: registry.BasicPassword, Hosts: hosts}},
		PlaceholderShape: registry.PlaceholderShape{MinLength: 32},
		EnvClass:         registry.EnvClassSpec{Default: registry.EnvProd},
		Adapter:          registry.Adapter{Kind: registry.AdapterDockerCredential, Field: "token", Username: "robot", Hosts: hosts},
		InjectionRules:   []registry.InjectionRule{{EnvVar: "REGISTRY_TOKEN", Source: "token"}},
	}
}

func TestDockerCredentialStoreSessionReturnsOnlyThePlaceholder(t *testing.T) {
	w := newContainedWorld(t)
	require.NoError(t, registry.Register(registryTemplate()))
	mgr, err := placeholder.NewManager(placeholder.Config{Resolver: fixedResolver{"token": "registry-real-token-0123456789"}, Audit: w.audit})
	require.NoError(t, err)
	t.Cleanup(mgr.Close)
	w.srv.cfg.Placeholders = mgr

	resp := session(t, w, &RunRequest{Connection: "regtest", Tier: TierPlaceholder, Command: []string{"docker"}})
	require.True(t, resp.OK, resp.Error)
	env := map[string]string{}
	for _, e := range resp.Session.Env.Set {
		env[e.Name] = e.Value
	}
	assert.Equal(t, runner.DockerConfigPlaceholder, env["DOCKER_CONFIG"])
	assert.Equal(t, resp.Session.ProxyID, env[runner.ProxySessionVar])
	placeholderValue := env["REGISTRY_TOKEN"]
	require.NotEmpty(t, placeholderValue)

	got := w.srv.credential(KindHuman, resp.Session.ProxyID, &CredentialRequest{Protocol: "https", Host: "registry.test.example"})
	require.NotNil(t, got.Credential)
	assert.Equal(t, "robot", got.Credential.Username)
	assert.Equal(t, placeholderValue, got.Credential.Password, "the helper answers with the session placeholder")
	assert.NotContains(t, got.Credential.Password, "registry-real-token")
	for name, host := range map[string]string{"another host": "evil.example", "a subdomain": "x.registry.test.example", "another port": "registry.test.example:5000"} {
		assert.Nil(t, w.srv.credential(KindHuman, resp.Session.ProxyID, &CredentialRequest{Protocol: "https", Host: host}).Credential, name)
	}

	binDir, cleanup, err := withDockerConfig(&resp.Session.Env, "/opt/keylatch/keylatch")
	require.NoError(t, err)
	defer cleanup()
	require.NotEmpty(t, binDir)
	for _, e := range resp.Session.Env.Set {
		if e.Name == "DOCKER_CONFIG" {
			cfg, err := os.ReadFile(filepath.Join(e.Value, "config.json"))
			require.NoError(t, err)
			assert.JSONEq(t, `{"credsStore":"keylatch"}`, string(cfg))
		}
	}
	script, err := os.ReadFile(filepath.Join(binDir, "docker-credential-keylatch"))
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/sh\nexec '/opt/keylatch/keylatch' docker-credential \"$@\"\n", string(script))
	info, err := os.Stat(filepath.Join(binDir, "docker-credential-keylatch"))
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&0o100, "the helper is executable")

	assert.Equal(t, []string{"A=1", "PATH=/helper:/usr/bin"}, prependPath([]string{"A=1", "PATH=/usr/bin"}, "/helper"))
	assert.Equal(t, []string{"A=1", "PATH=/helper"}, prependPath([]string{"A=1"}, "/helper"))

	none := runner.SessionEnv{Set: []runner.EnvAssign{{Name: "A", Value: "b"}}}
	bin, clean, err := withDockerConfig(&none, "")
	require.NoError(t, err)
	assert.Empty(t, bin)
	clean()
	_, _, err = withDockerConfig(&runner.SessionEnv{Set: []runner.EnvAssign{{Name: "DOCKER_CONFIG", Value: runner.DockerConfigPlaceholder}}}, "")
	assert.Error(t, err, "without the keylatch executable the helper cannot be installed")
}

func TestDockerCredentialHelperAnswersOnlyWithAPlaceholder(t *testing.T) {
	assert.Equal(t, "ghcr.io", registryHost("ghcr.io"))
	assert.Equal(t, "index.docker.io", registryHost("https://index.docker.io/v1/"))
	assert.Equal(t, "registry.example:5000", registryHost("registry.example:5000"))
	assert.Empty(t, registryHost(""))
	assert.Empty(t, registryHost("https://"))

	run := func(args []string, in string, session string) (int, string) {
		var out, errOut strings.Builder
		env := map[string]string{}
		if session != "" {
			env["KEYLATCH_PROXY_SESSION"] = session
		}
		code := RunDockerCredential(lookupOf(env), args, IO{In: strings.NewReader(in), Out: &out, ErrOut: &errOut})
		return code, out.String()
	}
	code, out := run([]string{"list"}, "", "")
	assert.Zero(t, code)
	assert.Equal(t, "{}\n", out)
	code, _ = run([]string{"store"}, `{"ServerURL":"ghcr.io","Username":"u","Secret":"s"}`+"\n", "")
	assert.Zero(t, code, "store is accepted and discarded")
	code, _ = run([]string{"erase"}, "ghcr.io\n", "")
	assert.Zero(t, code)

	code, out = run([]string{"get"}, "ghcr.io\n", "")
	assert.Equal(t, 1, code, "without a session there is nothing to give")
	assert.Contains(t, out, "credentials not found")
	code, out = run([]string{"get"}, "ghcr.io\n", "some-session")
	assert.Equal(t, 1, code, "without a daemon there is nothing to give")
	assert.Contains(t, out, "credentials not found")
	code, _ = run([]string{"bogus"}, "", "")
	assert.Equal(t, 1, code)
	code, _ = run(nil, "", "")
	assert.Equal(t, 1, code)
}
