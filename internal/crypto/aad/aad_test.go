package aad_test

import (
	"math/rand"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/aad"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// Fixture binding from spec §3.2.
var fixtureBinding = vmeta.AADBinding{
	SchemaVersion: 1,
	Namespace:     "default",
	Path:          "ai/openrouter/api_key",
	Version:       3,
	KeyTerm:       2,
	BackendID:     "file:0x4a",
	CreatedAt:     time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC),
	Algorithm:     "xchacha20-poly1305",
}

const fixtureExpected = `{"algorithm":"xchacha20-poly1305","backend_id":"file:0x4a","created_at":"2026-05-11T12:00:00Z","key_term":2,"namespace":"default","path":"ai/openrouter/api_key","schema_version":1,"version":3}`

func TestMarshalFixturePinned(t *testing.T) {
	got, err := aad.Marshal(fixtureBinding)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != fixtureExpected {
		t.Errorf("pinned byte mismatch:\ngot:  %s\nwant: %s", got, fixtureExpected)
	}
}

func TestMarshalDeterministic(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 1000; i++ {
		b := randomBinding(rng)
		first, err := aad.Marshal(b)
		if err != nil {
			t.Fatalf("iteration %d Marshal: %v", i, err)
		}
		second, err := aad.Marshal(b)
		if err != nil {
			t.Fatalf("iteration %d Marshal (2nd): %v", i, err)
		}
		if string(first) != string(second) {
			t.Fatalf("non-deterministic at iteration %d:\nfirst:  %s\nsecond: %s", i, first, second)
		}
	}
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	data, err := aad.Marshal(fixtureBinding)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := aad.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.SchemaVersion != fixtureBinding.SchemaVersion {
		t.Errorf("SchemaVersion: got %d, want %d", got.SchemaVersion, fixtureBinding.SchemaVersion)
	}
	if got.Namespace != fixtureBinding.Namespace {
		t.Errorf("Namespace: got %q, want %q", got.Namespace, fixtureBinding.Namespace)
	}
	if got.Path != fixtureBinding.Path {
		t.Errorf("Path: got %q, want %q", got.Path, fixtureBinding.Path)
	}
	if got.Version != fixtureBinding.Version {
		t.Errorf("Version: got %d, want %d", got.Version, fixtureBinding.Version)
	}
	if got.KeyTerm != fixtureBinding.KeyTerm {
		t.Errorf("KeyTerm: got %d, want %d", got.KeyTerm, fixtureBinding.KeyTerm)
	}
	if got.BackendID != fixtureBinding.BackendID {
		t.Errorf("BackendID: got %q, want %q", got.BackendID, fixtureBinding.BackendID)
	}
	if !got.CreatedAt.UTC().Equal(fixtureBinding.CreatedAt.UTC()) {
		t.Errorf("CreatedAt: got %v, want %v", got.CreatedAt, fixtureBinding.CreatedAt)
	}
	if got.Algorithm != fixtureBinding.Algorithm {
		t.Errorf("Algorithm: got %q, want %q", got.Algorithm, fixtureBinding.Algorithm)
	}
}

func randomBinding(rng *rand.Rand) vmeta.AADBinding {
	return vmeta.AADBinding{
		SchemaVersion: rng.Intn(10) + 1,
		Namespace:     randomString(rng, 8),
		Path:          randomString(rng, 16),
		Version:       rng.Intn(100) + 1,
		KeyTerm:       rng.Intn(10) + 1,
		BackendID:     "file:" + randomString(rng, 6),
		CreatedAt:     time.Unix(int64(rng.Intn(1e9)), 0).UTC(),
		Algorithm:     "xchacha20-poly1305",
	}
}

func randomString(rng *rand.Rand, n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rng.Intn(len(chars))]
	}
	return string(b)
}
