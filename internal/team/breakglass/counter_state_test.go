package breakglass_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team/breakglass"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mxCounterFile(t *testing.T, member string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	return filepath.Join(dir, "breakglass", "counter-hmac-"+member+".json")
}

func mxWriteCounter(t *testing.T, path string, v any) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	data, err := json.Marshal(v)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestCheckCoolingPeriod(t *testing.T) {
	ctx := context.Background()
	path := mxCounterFile(t, "carol")
	m := newMember("carol")

	assert.NoError(t, breakglass.CheckCoolingPeriod(ctx, m), "never closed means no cooling period")

	recent := time.Now().Add(-10 * time.Minute)
	mxWriteCounter(t, path, map[string]any{"opens": []time.Time{}, "last_close": recent})
	assert.ErrorIs(t, breakglass.CheckCoolingPeriod(ctx, m), breakglass.ErrCoolingPeriod)

	old := time.Now().Add(-2 * time.Hour)
	mxWriteCounter(t, path, map[string]any{"opens": []time.Time{}, "last_close": old})
	assert.NoError(t, breakglass.CheckCoolingPeriod(ctx, m))
}

func TestOpen_PrunesOpensOlderThanADay(t *testing.T) {
	ctx := context.Background()
	path := mxCounterFile(t, "dave")
	stale := time.Now().Add(-25 * time.Hour)
	mxWriteCounter(t, path, map[string]any{"opens": []time.Time{stale, stale, stale}})

	assert.NoError(t, breakglass.CheckRateLimit(ctx, newMember("dave")), "stale opens do not count")
	req, err := breakglass.Open(ctx, newMember("dave"), "incident")
	require.NoError(t, err)
	assert.Equal(t, breakglass.BGOpen, req.Status)
	assert.Equal(t, "breakglass/"+req.ID, req.AuditRef)
	assert.Regexp(t, `^[0-9a-f]{32}$`, req.ID)

	var c struct {
		Opens []time.Time `json:"opens"`
	}
	data, err := os.ReadFile(path) //nolint:gosec // temp path
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &c))
	assert.Len(t, c.Opens, 1, "stale entries are dropped when a new open is recorded")
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestCorruptCounterFailsClosed(t *testing.T) {
	ctx := context.Background()
	path := mxCounterFile(t, "erin")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte("{corrupt"), 0o600))
	m := newMember("erin")

	_, err := breakglass.Open(ctx, m, "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "corrupt counter file")
	assert.Error(t, breakglass.CheckRateLimit(ctx, m))
	assert.Error(t, breakglass.CheckCoolingPeriod(ctx, m))

	require.NoError(t, os.Remove(path))
	require.NoError(t, os.MkdirAll(path, 0o700))
	_, err = breakglass.Open(ctx, m, "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read counter")
}

func TestClose_RejectsNonOpenRequest(t *testing.T) {
	mxCounterFile(t, "frank")
	req := &breakglass.BreakGlassRequest{ID: "r1", Status: breakglass.BGClosed}
	err := breakglass.Close(context.Background(), req, newMember("frank"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not open")
}

func TestCounterStorageFailures(t *testing.T) {
	ctx := context.Background()
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	t.Setenv("KEYLATCH_TEAM_DIR", blocker)
	_, err := breakglass.Open(ctx, newMember("gina"), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mkdir")

	path := mxCounterFile(t, "gina")
	require.NoError(t, os.MkdirAll(path+".lock", 0o700))
	_, err = breakglass.Open(ctx, newMember("gina"), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "open lock file")

	path = mxCounterFile(t, "gina")
	require.NoError(t, os.MkdirAll(path+".tmp", 0o700))
	_, err = breakglass.Open(ctx, newMember("gina"), "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write counter")
}

func TestBreakglassDir_DefaultsUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KEYLATCH_TEAM_DIR", "")
	_, err := breakglass.Open(context.Background(), newMember("hank"), "x")
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(home, ".keylatch", "team", "breakglass", "counter-hmac-hank.json"))
	assert.NoError(t, err)
}
