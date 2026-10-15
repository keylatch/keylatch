package token

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/paths"
)

func authorityKey() []byte { return bytes.Repeat([]byte{3}, 32) }

func mintOne(t *testing.T, spec TokenSpec) (string, *Token, string) {
	t.Helper()
	store := filepath.Join(t.TempDir(), "tokens.json")
	spec.StorePath = store
	spec.SigningKey = authorityKey()
	if spec.Actor == "" {
		spec.Actor = "a"
	}
	jwt, tok, err := Mint(spec)
	if err != nil {
		t.Fatal(err)
	}
	return jwt, tok, store
}

// Editing a record cannot widen what the signed claims grant, even when the
// editor also holds a valid MAC for the record.
func TestStoreCannotWidenClaims(t *testing.T) {
	jwt, tok, store := mintOne(t, TokenSpec{Capabilities: []string{"p.read_one"}, MaxUses: 1, Kind: "agent", LLMSession: true})

	records, err := readTokens(store)
	if err != nil {
		t.Fatal(err)
	}
	records[0].Capabilities = []string{"p.*"}
	records[0].MaxUses = 0
	records[0].Kind = "human"
	records[0].LLMSession = false
	records[0].ExpiresAt = time.Now().Add(24 * time.Hour)
	sealRecord(authorityKey(), &records[0])
	if err := writeTokens(store, records); err != nil {
		t.Fatal(err)
	}

	got, err := Verify(jwt, nil, authorityKey(), store)
	if err != nil {
		t.Fatal(err)
	}
	if HasCapability(got, "p.other") || !HasCapability(got, "p.read_one") {
		t.Fatalf("capabilities came from the store: %v", got.Capabilities)
	}
	if got.MaxUses != 1 || got.Kind != "agent" || !got.LLMSession {
		t.Fatalf("claims overridden by the store: uses=%d kind=%q llm=%v", got.MaxUses, got.Kind, got.LLMSession)
	}
	if got.ExpiresAt.After(tok.ExpiresAt.Add(time.Second)) {
		t.Fatalf("expiry came from the store: %v", got.ExpiresAt)
	}
}

func TestStoreMACTamperRejected(t *testing.T) {
	jwt, _, store := mintOne(t, TokenSpec{Capabilities: []string{"p.a"}})

	records, err := readTokens(store)
	if err != nil {
		t.Fatal(err)
	}
	records[0].Actor = "someone-else"
	if err := writeTokens(store, records); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(jwt, nil, authorityKey(), store); !errors.Is(err, ErrStoreTampered) {
		t.Fatalf("edited record accepted: %v", err)
	}

	records[0].MAC = ""
	if err := writeTokens(store, records); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(jwt, nil, authorityKey(), store); !errors.Is(err, ErrStoreTampered) {
		t.Fatalf("unsealed record accepted: %v", err)
	}
}

func TestRevokeKeepsRecordsSealed(t *testing.T) {
	spec := TokenSpec{Capabilities: []string{"p.a"}}
	jwt, tok, store := mintOne(t, spec)
	if err := Revoke(tok.ID, store, authorityKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(jwt, nil, authorityKey(), store); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("want revoked, got %v", err)
	}
}

func TestDefaultTokenTTL(t *testing.T) {
	_, tok, _ := mintOne(t, TokenSpec{Capabilities: []string{"p.a"}})
	if got := tok.ExpiresAt.Sub(tok.IssuedAt); got != DefaultTTL || DefaultTTL != 10*time.Minute {
		t.Fatalf("default lifetime %v", got)
	}
	_, long, _ := mintOne(t, TokenSpec{Capabilities: []string{"p.a"}, TTL: 48 * time.Hour})
	if got := long.ExpiresAt.Sub(long.IssuedAt); got != MaxTTL {
		t.Fatalf("lifetime above the cap: %v", got)
	}
}

var signingTestParams = argon2.Params{Time: 1, Memory: 64 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32}

func TestSigningKeyMigrated(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_GATEWAY_SIGNING_KEY" {
			return filepath.Join(dir, "signing.key")
		}
		return ""
	}
	k, err := kek.PassphraseKEK([]byte("pw"), make([]byte, 32), signingTestParams)
	if err != nil {
		t.Fatal(err)
	}
	raw := bytes.Repeat([]byte{9}, 32)
	if err := os.WriteFile(paths.GatewaySigningKey(env), raw, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadSigningKey(env, k, false)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("migrated key differs: %v", err)
	}
	if _, err := os.Stat(paths.GatewaySigningKey(env)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("raw signing.key still exists: %v", err)
	}
	wrapped, err := os.ReadFile(paths.GatewaySigningKeyWrapped(env))
	if err != nil || bytes.Contains(wrapped, raw) {
		t.Fatalf("wrapped file missing or in the clear: %v", err)
	}
	again, err := LoadSigningKey(env, k, false)
	if err != nil || !bytes.Equal(again, raw) {
		t.Fatalf("reload after migration: %v", err)
	}
}

func TestSigningKeyCreatedOnlyWhenAsked(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		if k == "KEYLATCH_GATEWAY_SIGNING_KEY" {
			return filepath.Join(dir, "signing.key")
		}
		return ""
	}
	k, err := kek.PassphraseKEK([]byte("pw"), make([]byte, 32), signingTestParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(env, k, false); !errors.Is(err, ErrSigningKeyMissing) {
		t.Fatalf("want ErrSigningKeyMissing, got %v", err)
	}
	if _, err := LoadSigningKey(env, k, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.GatewaySigningKey(env)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a raw signing.key was written")
	}
}
