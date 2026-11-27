//go:build adapters

package adapters

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/adapter/mysql"
)

func TestMySQLClientUsesOnlyTheSessionToken(t *testing.T) {
	target, password := os.Getenv("KEYLATCH_TEST_MYSQL_ADDR"), os.Getenv("KEYLATCH_TEST_MYSQL_PASSWORD")
	if target == "" || password == "" {
		t.Skip("set KEYLATCH_TEST_MYSQL_ADDR and KEYLATCH_TEST_MYSQL_PASSWORD for MySQL conformance")
	}
	node, err := exec.LookPath("node")
	require.NoError(t, err)
	modules := os.Getenv("KEYLATCH_TEST_NODE_PG")
	require.NotEmpty(t, modules)
	srv, err := mysql.New(mysql.Config{Token: sessionToken, Target: target, User: "app_owner", Database: "appdb",
		TLS:      &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, // The disposable service generates its own certificate.
		Password: func(context.Context) ([]byte, error) { return []byte(password), nil },
		Report:   func(reason string) { t.Logf("adapter: %s", reason) },
	})
	require.NoError(t, err)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
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
	host, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	const script = `const mysql = require('mysql2/promise');
(async () => {
  const c = await mysql.createConnection({host:process.env.MYSQL_HOST,port:+process.env.MYSQL_TCP_PORT,user:'ignored',password:process.env.MYSQL_PWD,database:'appdb'});
  const [rows] = await c.execute('select current_user() as u');
  console.log(rows[0].u);
  await c.end();
})().catch(e => { console.error(e.message); process.exit(1); });`
	for _, credential := range []string{sessionToken, password} {
		cmd := exec.CommandContext(ctx, node, "-e", script)
		cmd.Env = []string{"MYSQL_HOST=" + host, "MYSQL_TCP_PORT=" + port, "MYSQL_PWD=" + credential, "NODE_PATH=" + modules}
		if credential == sessionToken {
			for _, v := range cmd.Env {
				if !strings.HasPrefix(v, "NODE_PATH=") {
					assert.NotContains(t, v, password)
				}
			}
		}
		out, err := cmd.CombinedOutput()
		if credential == sessionToken {
			require.NoError(t, err, string(out))
			assert.Equal(t, "app_owner@%", strings.TrimSpace(string(out)))
		} else {
			require.Error(t, err)
			assert.Contains(t, string(out), "authentication failed")
		}
	}
}
