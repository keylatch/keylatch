//go:build adapters

// Package adapters runs the protocol adapters against real servers. The tests
// need a PostgreSQL server (KEYLATCH_TEST_PG_ADDR, _USER, _PASSWORD,
// _DATABASE) and skip with the missing piece named when it is absent: a
// skipped test proves nothing, so the CI job provides them all.
package adapters

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/adapter/postgres"
)

const sessionToken = "klph_real_server_session_token_0123456789"

type server struct {
	addr, user, password, database string
}

func realServer(t *testing.T) server {
	t.Helper()
	s := server{
		addr: os.Getenv("KEYLATCH_TEST_PG_ADDR"), user: os.Getenv("KEYLATCH_TEST_PG_USER"),
		password: os.Getenv("KEYLATCH_TEST_PG_PASSWORD"), database: os.Getenv("KEYLATCH_TEST_PG_DATABASE"),
	}
	if s.addr == "" || s.user == "" || s.password == "" || s.database == "" {
		t.Skip("no PostgreSQL server: set KEYLATCH_TEST_PG_ADDR, KEYLATCH_TEST_PG_USER, KEYLATCH_TEST_PG_PASSWORD and KEYLATCH_TEST_PG_DATABASE")
	}
	return s
}

// startAdapter serves the real server through an adapter on loopback and
// returns its host and port.
func startAdapter(t *testing.T, s server) (host, port string) {
	t.Helper()
	srv, err := postgres.New(postgres.Config{
		Token: sessionToken, Target: s.addr, User: s.user, Database: s.database,
		Password:      func(context.Context) ([]byte, error) { return []byte(s.password), nil },
		PlainUpstream: true,
	})
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.Serve(ctx, c)
		}
	}()
	host, port, err = net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	return host, port
}

// childEnv is what a child gets: the adapter's address and the session token,
// and nothing else that could hold the database password.
func childEnv(host, port, token string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.TempDir(),
		"PGHOST=" + host, "PGPORT=" + port, "PGUSER=klph", "PGPASSWORD=" + token, "PGSSLMODE=disable",
	}
}

func TestPsqlLogsInWithOnlyTheSessionToken(t *testing.T) {
	s := realServer(t)
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skip("psql is not installed")
	}
	host, port := startAdapter(t, s)

	cmd := exec.Command("psql", "-d", s.database, "-tAc", "select current_user")
	cmd.Env = childEnv(host, port, sessionToken)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, s.user, strings.TrimSpace(string(out)), "the server saw the stored role, not the client's user name")
	for _, e := range cmd.Env {
		assert.NotContains(t, e, s.password, "the child's environment never held the database password")
	}
}

func TestPsqlWithTheDatabasePasswordIsRefused(t *testing.T) {
	s := realServer(t)
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skip("psql is not installed")
	}
	host, port := startAdapter(t, s)

	cmd := exec.Command("psql", "-d", s.database, "-tAc", "select 1")
	cmd.Env = childEnv(host, port, s.password)
	out, err := cmd.CombinedOutput()
	require.Error(t, err, "only the session token opens the adapter")
	assert.Contains(t, string(out), "password authentication failed")
}

func TestNodePgClientLogsInWithOnlyTheSessionToken(t *testing.T) {
	s := realServer(t)
	modules := os.Getenv("KEYLATCH_TEST_NODE_PG")
	node, err := exec.LookPath("node")
	if modules == "" || err != nil {
		t.Skip("node and the pg driver are not available: set KEYLATCH_TEST_NODE_PG to a node_modules directory holding pg")
	}
	host, port := startAdapter(t, s)

	const script = `
const { Client } = require('pg');
(async () => {
  const c = new Client({ host: process.env.PGHOST, port: +process.env.PGPORT, user: process.env.PGUSER,
    password: process.env.PGPASSWORD, database: process.env.PGDATABASE, ssl: false });
  await c.connect();
  const r = await c.query('select current_user as u');
  console.log(r.rows[0].u);
  await c.end();
})().catch(e => { console.error(e.message); process.exit(1); });`
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "-e", script)
	cmd.Env = append(childEnv(host, port, sessionToken), "NODE_PATH="+modules, "PGDATABASE="+s.database)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	assert.Equal(t, s.user, strings.TrimSpace(string(out)))
}
