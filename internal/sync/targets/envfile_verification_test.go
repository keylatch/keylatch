package targets

import (
	"context"
	"errors"
	"strings"
	"testing"

	keysync "github.com/keylatch/keylatch/internal/sync"
	"github.com/stretchr/testify/require"
)

func TestEnvFileVerifiesFlushedContent(t *testing.T) {
	ctx := context.Background()
	value := []byte("new 'quoted'\nvalue $with \\")
	var disk []byte
	f := NewEnvFile("local", []byte("# keep\nKEY=old\nexport KEY=duplicate\nOTHER=1\n"), func(b []byte) error {
		disk = append([]byte(nil), b...)
		return nil
	})
	f.read = func() ([]byte, error) { return append([]byte(nil), disk...), nil }
	r := keysync.Remote{Name: "KEY", Environments: []string{keysync.EnvFile}}
	require.NoError(t, f.Write(ctx, "KEY", value, nil, false))
	require.Error(t, f.VerifyValue(ctx, r, value))
	require.NoError(t, f.Flush(ctx))
	require.Equal(t, 1, strings.Count(string(disk), "KEY="))
	require.Contains(t, string(disk), "# keep\n")
	require.Contains(t, string(disk), "OTHER=1\n")
	require.NoError(t, f.VerifyValue(ctx, r, value))
	require.Error(t, f.VerifyValue(ctx, r, []byte("wrong")))
	disk = []byte("KEY=dropped-write\n")
	require.Error(t, f.VerifyValue(ctx, r, value))
	f.read = func() ([]byte, error) { return nil, errors.New("read failed") }
	require.Error(t, f.VerifyValue(ctx, r, value))
	f.read = nil
	require.Error(t, f.VerifyValue(ctx, r, value))
}
