package api

import (
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/runner"
)

// TestReceiptStore_PushUnsubscribeRace hammers Push concurrently with
// subscribe/unsubscribe cycles. Regression test for a send-on-closed-channel
// panic: Push used to snapshot subscribers and send after releasing the lock,
// racing with unsubscribe's close(ch). Run with -race.
func TestReceiptStore_PushUnsubscribeRace(t *testing.T) {
	store := NewReceiptStore(64)

	const (
		pushers     = 4
		subscribers = 4
		iterations  = 500
	)

	done := make(chan struct{})
	var pushWG, subWG sync.WaitGroup

	for i := 0; i < pushers; i++ {
		pushWG.Add(1)
		go func() {
			defer pushWG.Done()
			for {
				select {
				case <-done:
					return
				default:
					store.Push(runner.RuntimeReceipt{})
				}
			}
		}()
	}

	for i := 0; i < subscribers; i++ {
		subWG.Add(1)
		go func() {
			defer subWG.Done()
			for j := 0; j < iterations; j++ {
				ch := store.subscribe()
				// Drain at most one pending receipt, then tear down while
				// pushers are still sending.
				select {
				case <-ch:
				default:
				}
				store.unsubscribe(ch)
			}
		}()
	}

	subWG.Wait()
	close(done)
	pushWG.Wait()
}
