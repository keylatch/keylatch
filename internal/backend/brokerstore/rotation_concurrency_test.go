package brokerstore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/stretchr/testify/require"
)

type pausedStoreKeys struct {
	*keys.Hierarchy
	armed   atomic.Bool
	entered chan struct{}
	resume  chan struct{}
}

func (p *pausedStoreKeys) StoreKEK(partition string) (string, []byte) {
	kid, key := p.Hierarchy.StoreKEK(partition)
	if p.armed.Swap(false) {
		close(p.entered)
		<-p.resume
	}
	return kid, key
}

func TestMasterKeyReplacementWaitsForStoreCommit(t *testing.T) {
	for _, operation := range []string{"put", "retire"} {
		for _, recovery := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/rotate", true: "/resume"}[recovery], func(t *testing.T) {
				ctx := context.Background()
				h := newKeys(t)
				p := &pausedStoreKeys{Hierarchy: h, entered: make(chan struct{}), resume: make(chan struct{})}
				dir := t.TempDir()
				s, err := Open(dir, "1000", p)
				require.NoError(t, err)
				ref := retirementFixture(t, s)
				if recovery {
					interrupted := errors.New("interrupted rewrap")
					require.ErrorIs(t, h.Rotate(func(keys.KEKFunc, keys.KEKFunc, string) error { return interrupted }), interrupted)
				}
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(p.resume) }) }
				defer release()
				p.armed.Store(true)
				committed := make(chan error, 1)
				go func() {
					if operation == "retire" {
						committed <- s.Retire(ctx, ref)
					} else {
						_, err := s.Put(ctx, "app/key", []byte("latest"))
						committed <- err
					}
				}()
				select {
				case <-p.entered:
				case <-time.After(5 * time.Second):
					t.Fatal("store did not reach encryption")
				}
				rotated := make(chan error, 1)
				go func() {
					rewrap := func(old, next keys.KEKFunc, id string) error {
						other, err := Open(dir, "1000", h)
						if err != nil {
							return err
						}
						_, err = other.Rewrap(old("1000"), next("1000"), id)
						return err
					}
					if recovery {
						rotated <- h.Resume(rewrap)
					} else {
						rotated <- h.Rotate(rewrap)
					}
				}()
				select {
				case err := <-rotated:
					t.Fatalf("master key replaced before the store committed: %v", err)
				case <-time.After(30 * time.Millisecond):
				}
				release()
				select {
				case err := <-committed:
					require.NoError(t, err)
				case <-time.After(5 * time.Second):
					t.Fatal("store commit deadlocked")
				}
				select {
				case err := <-rotated:
					require.NoError(t, err)
				case <-time.After(5 * time.Second):
					t.Fatal("master key replacement deadlocked")
				}
				current, _, err := s.Get(ctx, "app/key")
				require.NoError(t, err)
				if operation == "retire" {
					require.Equal(t, "current-secret", string(current))
					require.NoError(t, s.Retire(ctx, ref))
					_, _, err = s.GetVersion(ctx, "app/key", 1)
					require.ErrorIs(t, err, ErrRetired)
				} else {
					require.Equal(t, "latest", string(current))
					old, _, err := s.GetVersion(ctx, "app/key", 2)
					require.NoError(t, err)
					require.Equal(t, "current-secret", string(old))
					clear(old)
				}
				clear(current)
			})
		}
	}
}
