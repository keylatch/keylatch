package contained

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestLandlockMaskGrowsWithTheABI(t *testing.T) {
	v1, v2, v3, v5 := fsMask(1), fsMask(2), fsMask(3), fsMask(5)
	assert.Zero(t, v1&unix.LANDLOCK_ACCESS_FS_REFER)
	assert.NotZero(t, v2&unix.LANDLOCK_ACCESS_FS_REFER)
	assert.Zero(t, v2&unix.LANDLOCK_ACCESS_FS_TRUNCATE)
	assert.NotZero(t, v3&unix.LANDLOCK_ACCESS_FS_TRUNCATE)
	assert.Zero(t, v3&unix.LANDLOCK_ACCESS_FS_IOCTL_DEV)
	assert.NotZero(t, v5&unix.LANDLOCK_ACCESS_FS_IOCTL_DEV)
}

func TestLandlockPlanListsExistingPathsOnly(t *testing.T) {
	dir := t.TempDir()
	plan := newLandlockPlan(4, []string{dir, filepath.Join(dir, "missing")}, []string{dir}, []int{3128, 8080})
	require.Len(t, plan.paths, 2)
	assert.Equal(t, uint64(fsAccessReadExe)&fsMask(4), plan.paths[0].access, "read-only paths get read and execute")
	assert.Equal(t, fsMask(4), plan.paths[1].access, "read-write paths get every right")
	assert.Equal(t, uint64(unix.LANDLOCK_ACCESS_NET_CONNECT_TCP), plan.netHandled)
	assert.Equal(t, []uint16{3128, 8080}, plan.ports)
}

func TestLandlockPlanWithoutNetworkRules(t *testing.T) {
	plan := newLandlockPlan(3, nil, nil, []int{3128})
	assert.Zero(t, plan.netHandled)
	assert.Empty(t, plan.ports)
}

func TestLandlockABIOfThisKernel(t *testing.T) {
	assert.GreaterOrEqual(t, landlockABI(), 0)
}
