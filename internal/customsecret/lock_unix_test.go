//go:build linux || darwin || freebsd || netbsd || openbsd

package customsecret

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLockWaitIsBoundedAndNamesTheLockFile(t *testing.T) {
	prev := lockWait
	lockWait = 150 * time.Millisecond
	t.Cleanup(func() { lockWait = prev })
	path := filepath.Join(t.TempDir(), "custom-secrets.json")

	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = WithLock(path, func(Tx) error {
			close(held)
			<-release
			return nil
		})
	}()
	<-held

	start := time.Now()
	err := WithLock(path, func(Tx) error { return nil })
	require.Error(t, err)
	assert.Contains(t, err.Error(), path+".lock")
	assert.Less(t, time.Since(start), 5*time.Second)

	close(release)
	<-done
	require.NoError(t, WithLock(path, func(Tx) error { return nil }), "the lock is usable again once released")
}
