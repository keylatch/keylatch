package argon2_test

// argon2_extra_test.go adds coverage for uncovered branches:
//   - Derive: KeyLen == 0 error path
//   - Calibrate: targetMs <= 0 fast path (returns Recommended2026)
//   - Calibrate: valid calibration targeting very short time (exercises the binary search)

import (
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
)

// ---------------------------------------------------------------------------
// Derive — error paths
// ---------------------------------------------------------------------------

func TestDerive_ZeroKeyLen_Error(t *testing.T) {
	t.Parallel()
	_, err := argon2.Derive([]byte("pass"), make([]byte, 16), argon2.Params{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 1,
		SaltLen: 16,
		KeyLen:  0, // must error
	})
	if err == nil {
		t.Error("expected error for KeyLen=0, got nil")
	}
}

func TestDerive_ValidKeyLen(t *testing.T) {
	t.Parallel()
	// KeyLen=16 is valid (non-32 key length).
	key, err := argon2.Derive([]byte("pass"), make([]byte, 16), argon2.Params{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 1,
		SaltLen: 16,
		KeyLen:  16,
	})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if len(key) != 16 {
		t.Errorf("key len = %d, want 16", len(key))
	}
}

// ---------------------------------------------------------------------------
// Calibrate — fast path (targetMs <= 0)
// ---------------------------------------------------------------------------

func TestCalibrate_ZeroTarget(t *testing.T) {
	t.Parallel()
	p, err := argon2.Calibrate(0)
	if err != nil {
		t.Fatalf("Calibrate(0): %v", err)
	}
	// Must return Recommended2026 verbatim.
	want := argon2.Recommended2026
	if p != want {
		t.Errorf("Calibrate(0) = %+v, want %+v", p, want)
	}
}

func TestCalibrate_NegativeTarget(t *testing.T) {
	t.Parallel()
	p, err := argon2.Calibrate(-1)
	if err != nil {
		t.Fatalf("Calibrate(-1): %v", err)
	}
	if p != argon2.Recommended2026 {
		t.Errorf("Calibrate(-1) should return Recommended2026")
	}
}

// ---------------------------------------------------------------------------
// Calibrate — binary search exercises (short target triggers low = mid + 1)
// ---------------------------------------------------------------------------

// TestCalibrate_VeryShortTarget uses a 1ms target. On any modern machine
// argon2id Time=1 takes more than 1ms, so the search may immediately conclude
// at mid=1 and return Time=1. This exercises the "within tolerance" or
// "too slow at mid=1" branches.
func TestCalibrate_VeryShortTarget(t *testing.T) {
	t.Parallel()
	p, err := argon2.Calibrate(1)
	if err != nil {
		t.Fatalf("Calibrate(1ms): %v", err)
	}
	if p.Time < 1 {
		t.Error("calibrated Time must be >= 1")
	}
	if p.KeyLen != 32 {
		t.Errorf("KeyLen = %d, want 32", p.KeyLen)
	}
}

// TestCalibrate_LongTarget exercises the upper search range (high = mid - 1).
// Using a 10ms target on a fast machine could push Time > 1.
func TestCalibrate_MediumTarget(t *testing.T) {
	t.Parallel()
	p, err := argon2.Calibrate(50) // 50ms — reasonable without being too slow
	if err != nil {
		t.Fatalf("Calibrate(50ms): %v", err)
	}
	if p.Time < 1 {
		t.Error("calibrated Time must be >= 1")
	}
	if p.Memory != argon2.Recommended2026.Memory {
		t.Errorf("Memory = %d, want %d", p.Memory, argon2.Recommended2026.Memory)
	}
}
