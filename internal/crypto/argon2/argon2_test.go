package argon2_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
)

func TestDeriveBasic(t *testing.T) {
	pass := []byte("password")
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	key, err := argon2.Derive(pass, salt, argon2.Params{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 1,
		SaltLen: 32,
		KeyLen:  32,
	})
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key len = %d, want 32", len(key))
	}

	// Deterministic.
	key2, err := argon2.Derive(pass, salt, argon2.Params{
		Time:    1,
		Memory:  64 * 1024,
		Threads: 1,
		SaltLen: 32,
		KeyLen:  32,
	})
	if err != nil {
		t.Fatalf("Derive 2: %v", err)
	}
	if string(key) != string(key2) {
		t.Error("Derive is not deterministic")
	}
}

func TestDeriveErrorOnEmptySalt(t *testing.T) {
	_, err := argon2.Derive([]byte("pass"), nil, argon2.Recommended2026)
	if err == nil {
		t.Error("expected error for empty salt")
	}
}

func TestRecommended2026Params(t *testing.T) {
	p := argon2.Recommended2026
	if p.Time < 1 {
		t.Error("Time must be >= 1")
	}
	if p.Memory < 64*1024 {
		t.Errorf("Memory = %d KiB, want >= 64 MiB", p.Memory)
	}
	if p.Threads < 1 {
		t.Error("Threads must be >= 1")
	}
	if p.KeyLen != 32 {
		t.Errorf("KeyLen = %d, want 32", p.KeyLen)
	}
}

// katVector is the JSON structure for the Argon2id KAT vector file.
type katVector struct {
	Description string `json:"description"`
	Time        uint32 `json:"time"`
	Memory      uint32 `json:"memory"`
	Threads     uint8  `json:"threads"`
	KeyLen      uint32 `json:"key_len"`
	Passphrase  string `json:"passphrase"`
	Salt        string `json:"salt"`
	Expected    string `json:"expected"`
}

// TestKATVector reads testdata/argon2id-rfc9106.json and verifies each vector.
func TestKATVector(t *testing.T) {
	data, err := os.ReadFile("testdata/argon2id-rfc9106.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	var vectors []katVector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse testdata: %v", err)
	}

	if len(vectors) == 0 {
		t.Fatal("no KAT vectors found in testdata/argon2id-rfc9106.json")
	}

	for _, v := range vectors {
		v := v
		t.Run(v.Description, func(t *testing.T) {
			params := argon2.Params{
				Time:    v.Time,
				Memory:  v.Memory,
				Threads: v.Threads,
				SaltLen: uint32(len(v.Salt)),
				KeyLen:  v.KeyLen,
			}
			got, err := argon2.Derive([]byte(v.Passphrase), []byte(v.Salt), params)
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}
			want, err := hex.DecodeString(v.Expected)
			if err != nil {
				t.Fatalf("decode expected hex: %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("KAT mismatch:\n  got  %x\n  want %x", got, want)
			}
		})
	}
}

func TestCalibrateReturnsValidParams(t *testing.T) {
	p, err := argon2.Calibrate(100) // 100ms target for test speed
	if err != nil {
		t.Fatalf("Calibrate: %v", err)
	}
	if p.Time < 1 {
		t.Error("calibrated Time < 1")
	}
	if p.Memory != argon2.Recommended2026.Memory {
		t.Error("calibrated Memory differs from Recommended2026")
	}
	if p.KeyLen != 32 {
		t.Error("calibrated KeyLen != 32")
	}
}
