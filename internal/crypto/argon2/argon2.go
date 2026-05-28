// Package argon2 provides the Argon2id KDF wrapper and calibration helper used
// by PassphraseKEK for DEK wrapping key derivation.
package argon2

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

// Params holds the Argon2id parameters.
type Params struct {
	Time    uint32
	Memory  uint32 // KiB
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// Recommended2026 are the Argon2id parameters recommended for 2026.
// These target approximately 200ms on a modern laptop.
// RFC 9106 §4 minimum: Time=1, Memory=64*1024, Threads=4.
var Recommended2026 = Params{
	Time:    3,
	Memory:  64 * 1024, // 64 MiB
	Threads: 4,
	SaltLen: 32,
	KeyLen:  32,
}

// Derive derives a key from passphrase and salt using Argon2id.
// Returns a KeyLen-byte key.
func Derive(passphrase, salt []byte, p Params) ([]byte, error) {
	if len(salt) == 0 {
		return nil, errors.New("argon2: salt must not be empty")
	}
	if p.KeyLen == 0 {
		return nil, errors.New("argon2: KeyLen must be > 0")
	}
	key := argon2.IDKey(passphrase, salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return key, nil
}

// Calibrate benchmarks the current machine and returns Params that achieve
// approximately targetMs milliseconds (within ±20%). The memory parameter
// is kept at the Recommended2026 value (64 MiB); only Time is adjusted.
//
// Returns Recommended2026 if targetMs <= 0 or calibration is not needed.
func Calibrate(targetMs int) (Params, error) {
	if targetMs <= 0 {
		return Recommended2026, nil
	}

	p := Params{
		Time:    1,
		Memory:  Recommended2026.Memory,
		Threads: Recommended2026.Threads,
		SaltLen: Recommended2026.SaltLen,
		KeyLen:  Recommended2026.KeyLen,
	}

	salt := make([]byte, p.SaltLen)
	pass := []byte("calibration-passphrase")

	// Binary search for the optimal Time parameter (1..32).
	low, high := uint32(1), uint32(32)
	target := time.Duration(targetMs) * time.Millisecond

	for low < high {
		mid := (low + high) / 2
		p.Time = mid

		start := time.Now()
		_, err := Derive(pass, salt, p)
		if err != nil {
			return Params{}, fmt.Errorf("argon2: calibrate derive: %w", err)
		}
		elapsed := time.Since(start)

		if elapsed < target*8/10 { // more than 20% under
			low = mid + 1
		} else if elapsed > target*12/10 { // more than 20% over
			if mid == 1 {
				break
			}
			high = mid - 1
		} else {
			break // within 20% of target
		}
	}

	return p, nil
}
