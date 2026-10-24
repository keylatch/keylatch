//go:build adapters

package mysql

import (
	"context"
	"crypto/tls"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpstreamServiceAuthentication(t *testing.T) {
	target, password := os.Getenv("KEYLATCH_TEST_MYSQL_ADDR"), os.Getenv("KEYLATCH_TEST_MYSQL_PASSWORD")
	if target == "" || password == "" {
		t.Skip("MySQL conformance service is not configured")
	}
	s, err := New(Config{Token: "klph_session", Target: target, User: "app_owner", Database: "appdb", TLS: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, Password: func(context.Context) ([]byte, error) { return []byte(password), nil }})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	up, err := s.connect(ctx, login{caps: capabilities, charset: 45, database: "appdb"})
	require.NoError(t, err)
	require.NoError(t, up.Close())
}
