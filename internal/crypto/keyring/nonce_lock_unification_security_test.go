package keyring

// TestSecurityRegression_ConcurrentRotateKEKMustNotRollBackGCMNonceCounter
// simulates two processes sharing one keyring.json: process A is mid-flight
// in NextGCMNonce (has reloaded the disk counter but not yet flushed its new
// high-watermark); process B concurrently runs RotateKEK, which reloads the
// same (still-stale) counter and later saves the whole keyring back.
//
// Before the fix, NextGCMNonce and RotateKEK/RotateTerm/DestroyTerm guarded
// their disk writes with two DIFFERENT flock files, so B was never blocked
// by A and could reload A's pre-flush snapshot, then save it back AFTER A's
// flush — silently rolling the on-disk nonce counter back down. A process
// that then allocates nonces from the rolled-back counter would reuse an
// AES-GCM nonce, breaking confidentiality/integrity for the colliding
// ciphertexts.
//
// After the fix, both operations flock the same lockPath, so B blocks until
// A releases; as extra defense-in-depth, mergeGCMCounters also makes any
// reload take the max() of what's already known in memory, so even the
// exact interleaving forced below cannot move the disk counter backward.
import (
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
)

func TestSecurityRegression_ConcurrentRotateKEKMustNotRollBackGCMNonceCounter(t *testing.T) {
	dir := t.TempDir()
	krA, krPath := buildGCMKeyring(t, dir, "nonce-lock-race", 0) // leaseSize=0: strict, flush every nonce
	defer krA.Zero()

	// Second process: an independent Keyring handle opened on the same file
	// with the same KEK (same passphrase/salt as buildGCMKeyring uses).
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 3)
	}
	params := argon2.Params{Time: 1, Memory: 16 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}
	kA, err := kek.PassphraseKEK([]byte("nonce-lock-race"), salt, params)
	if err != nil {
		t.Fatalf("PassphraseKEK: %v", err)
	}
	krB, err := Open(filepath.Join(dir, "keyring.json"), kA)
	if err != nil {
		t.Fatalf("Open second handle: %v", err)
	}
	defer krB.Zero()

	reloadASignaled := make(chan struct{})
	reloadBDone := make(chan struct{})
	saveADone := make(chan struct{})

	// A: after reloading (inside NextGCMNonce's slow path, lock held),
	// signal readiness, then wait briefly for B to have reloaded its own
	// (still-stale, in a buggy build) snapshot before flushing.
	krA.fsyncFailHook = func() error {
		close(reloadASignaled)
		select {
		case <-reloadBDone:
		case <-time.After(2 * time.Second):
			// Fixed build: B is blocked acquiring the shared lock and never
			// reaches its reload — proceed, this is the correct outcome.
		}
		if err := saveFile(krA.path, krA.file); err != nil {
			return err
		}
		close(saveADone)
		return nil
	}

	// B: after RotateKEK reloads (inside its own lock), rendezvous with A
	// then wait for A's flush to land on disk before B's own save runs.
	krB.postReloadHook = func() {
		select {
		case <-reloadASignaled:
		case <-time.After(2 * time.Second):
		}
		select {
		case <-reloadBDone:
		default:
			close(reloadBDone)
		}
		select {
		case <-saveADone:
		case <-time.After(2 * time.Second):
		}
	}

	doneA := make(chan error, 1)
	doneB := make(chan error, 1)
	go func() {
		_, err := krA.NextGCMNonce(1)
		doneA <- err
	}()
	go func() {
		doneB <- krB.RotateKEK(kA)
	}()

	if err := <-doneA; err != nil {
		t.Fatalf("NextGCMNonce: %v", err)
	}
	if err := <-doneB; err != nil {
		t.Fatalf("RotateKEK: %v", err)
	}

	kf, err := loadFile(krPath)
	if err != nil {
		t.Fatalf("loadFile: %v", err)
	}
	if kf.GCMState == nil {
		t.Fatal("GCMState missing after concurrent rotate")
	}
	if got := kf.GCMState.PerTerm[1]; got < 1 {
		t.Errorf("nonce counter for term 1 rolled back to %d after concurrent RotateKEK; "+
			"a subsequent NextGCMNonce would reuse a nonce", got)
	}
}
