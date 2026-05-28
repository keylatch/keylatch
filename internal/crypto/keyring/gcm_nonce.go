package keyring

import (
	"fmt"
	"math"
)

// gcmNonceLease tracks a pre-allocated block of nonce values for a single term.
// Durable-lease optimization: instead of one fsync per nonce, allocate a batch.
type gcmNonceLease struct {
	term    int
	current uint64 // next counter to hand out within the current lease
	end     uint64 // exclusive end of this lease (uninitialized when current == end == 0 and term == 0)
	valid   bool   // true once the lease has been initialized for at least one term
}

// exhausted reports whether the in-process lease needs to be refreshed.
func (l *gcmNonceLease) exhausted(term int) bool {
	return !l.valid || l.term != term || l.current >= l.end
}

// NextGCMNonce returns a fresh 12-byte AES-GCM nonce for the given term.
//
// The nonce is formatted as: uint32(term) || uint64(counter) big-endian.
//
// In-process lease optimization: disk writes happen only once per leaseSize
// calls. Within a lease, nonces are handed out from the in-process counter
// with no disk I/O.
//
// Cross-process uniqueness is guaranteed via:
//  1. flock on <keyring-dir>/keyring-gcm-nonce.lock
//  2. Re-read of keyring.json from disk after acquiring the flock
//  3. Atomic flush of the high-watermark BEFORE the lease is used
//
// If the flush fails, the in-process counter is rolled back and
// ErrNonceCounterFlushFailed is returned. The caller must not encrypt.
//
// At MaxUint64, returns ErrKeyTermExhausted.
func (kr *Keyring) NextGCMNonce(term int) ([]byte, error) {
	kr.mu.Lock()
	defer kr.mu.Unlock()

	// Fast path: hand out from the in-process lease with no disk I/O.
	if !kr.lease.exhausted(term) {
		nonce := encodeGCMNonce(term, kr.lease.current)
		kr.lease.current++
		return nonce, nil
	}

	// Slow path: lease exhausted or uninitialized — allocate a new lease.
	// Acquire inter-process flock before touching the disk counter.
	unlock, err := acquireFlock(kr.gcmFlock)
	if err != nil {
		return nil, fmt.Errorf("NextGCMNonce: flock: %w", err)
	}
	defer unlock()

	// Re-load keyring from disk (another process may have advanced the counter).
	kf, err := loadFile(kr.path)
	if err != nil {
		return nil, fmt.Errorf("NextGCMNonce: reload keyring: %w", err)
	}
	kr.file = kf

	if kr.file.GCMState == nil {
		return nil, fmt.Errorf("NextGCMNonce: GCM state not initialized")
	}

	diskCounter, ok := kr.file.GCMState.PerTerm[term]
	if !ok {
		return nil, fmt.Errorf("%w: GCM nonce counter for term %d not found", ErrKeyTermNotFound, term)
	}

	if diskCounter == math.MaxUint64 {
		return nil, ErrKeyTermExhausted
	}

	leaseSize := kr.file.GCMState.LeaseSize
	var leaseStart, leaseEnd uint64

	leaseStart = diskCounter
	if leaseSize > 0 {
		// Lease mode: pre-allocate leaseSize nonces; flush high-watermark once.
		if diskCounter > math.MaxUint64-leaseSize {
			leaseEnd = math.MaxUint64
		} else {
			leaseEnd = diskCounter + leaseSize
		}
	} else {
		// Strict mode: one nonce per flush.
		leaseEnd = diskCounter + 1
	}

	// Flush the high-watermark to disk BEFORE using any nonce in this lease.
	kr.file.GCMState.PerTerm[term] = leaseEnd

	var flushErr error
	if kr.fsyncFailHook != nil {
		flushErr = kr.fsyncFailHook()
	} else {
		flushErr = saveFile(kr.path, kr.file)
	}

	if flushErr != nil {
		// Rollback: restore previous disk counter in memory.
		kr.file.GCMState.PerTerm[term] = diskCounter
		return nil, ErrNonceCounterFlushFailed
	}

	// Lease allocated successfully. Update in-process lease.
	kr.lease = gcmNonceLease{
		term:    term,
		current: leaseStart + 1, // leaseStart is the nonce we're about to return
		end:     leaseEnd,
		valid:   true,
	}

	return encodeGCMNonce(term, leaseStart), nil
}
