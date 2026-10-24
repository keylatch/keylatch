//go:build adapters

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

	"github.com/keylatch/keylatch/internal/adapter/redis"
)

func TestRedisClientUsesOnlyTheSessionToken(t *testing.T) {
	target, password := os.Getenv("KEYLATCH_TEST_REDIS_ADDR"), os.Getenv("KEYLATCH_TEST_REDIS_PASSWORD")
	if target == "" || password == "" {
		t.Skip("set KEYLATCH_TEST_REDIS_ADDR and KEYLATCH_TEST_REDIS_PASSWORD for Redis conformance")
	}
	binary, err := exec.LookPath("redis-cli")
	require.NoError(t, err)
	srv, err := redis.New(redis.Config{Token: sessionToken, Target: target, PlainUpstream: true,
		Password: func(context.Context) ([]byte, error) { return []byte(password), nil },
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
	for _, protocol := range []string{"-2", "-3"} {
		t.Run(protocol, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, binary, protocol, "--raw", "-h", host, "-p", port, "ACL", "WHOAMI")
			cmd.Env = []string{"REDISCLI_AUTH=" + sessionToken}
			for _, v := range append(cmd.Args, cmd.Env...) {
				assert.NotContains(t, v, password)
			}
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, string(out))
			assert.Equal(t, "default", strings.TrimSpace(string(out)))
		})
	}
	cmd := exec.CommandContext(ctx, binary, "--raw", "-h", host, "-p", port, "PING")
	cmd.Env = []string{"REDISCLI_AUTH=" + password}
	out, _ := cmd.CombinedOutput()
	assert.Contains(t, string(out), "WRONGPASS")
	assert.NotContains(t, string(out), "PONG")
}
