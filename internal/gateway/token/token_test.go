package token_test

import (
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/token"
)

func testSigningKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func testStorePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "gateway-tokens.json")
}

func TestMint_ProducesVerifiableJWT(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	jwtStr, tok, err := token.Mint(token.TokenSpec{
		Actor:        "test-actor",
		Capabilities: []string{"openrouter.chat"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if jwtStr == "" {
		t.Fatal("expected non-empty JWT")
	}
	if tok.ID == "" {
		t.Fatal("expected non-empty token ID")
	}
	if tok.Accessor == "" {
		t.Fatal("expected non-empty accessor")
	}

	// Verify the JWT.
	verified, err := token.Verify(jwtStr, nil, key, storePath)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Actor != "test-actor" {
		t.Errorf("actor: got %q, want %q", verified.Actor, "test-actor")
	}
}

func TestVerify_RejectsRevoked(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	jwtStr, tok, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"cap"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := token.Revoke(tok.ID, storePath); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err = token.Verify(jwtStr, nil, key, storePath)
	if err == nil {
		t.Fatal("expected error for revoked token")
	}
	if err != token.ErrTokenRevoked {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestVerify_RejectsWrongSignature(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"cap"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Use different key.
	wrongKey := testSigningKey(t)
	_, err = token.Verify(jwtStr, nil, wrongKey, storePath)
	if err == nil {
		t.Fatal("expected error for wrong signature")
	}
}

func TestVerify_FDNonceMismatch(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"cap"},
		TTL:          1 * time.Hour,
		FDNonce:      nonce,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Request with no nonce header → mismatch.
	req := httptest.NewRequest("POST", "/api/test/action", nil)
	_, err = token.Verify(jwtStr, req, key, storePath)
	if err != token.ErrFDNonceMismatch {
		t.Errorf("expected ErrFDNonceMismatch, got %v", err)
	}
}

func TestVerify_FDNonce_ValidHeader(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"cap"},
		TTL:          1 * time.Hour,
		FDNonce:      nonce,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/api/test/action", nil)
	req.Header.Set("X-Keylatch-FD-Nonce", base64.StdEncoding.EncodeToString(nonce))

	verified, err := token.Verify(jwtStr, req, key, storePath)
	if err != nil {
		t.Errorf("expected no error with correct nonce, got %v", err)
	}
	if verified == nil {
		t.Fatal("expected non-nil token")
	}
}

func TestVerify_MaxUses_AtomicDecrement(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"cap"},
		TTL:          1 * time.Hour,
		MaxUses:      3,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3 concurrent goroutines; exactly 3 should succeed (MaxUses=3).
	const goroutines = 3
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, verifyErr := token.Verify(jwtStr, nil, key, storePath)
			mu.Lock()
			if verifyErr == nil {
				successCount++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if successCount != goroutines {
		t.Errorf("expected %d successes, got %d", goroutines, successCount)
	}

	// One more attempt should fail.
	_, err = token.Verify(jwtStr, nil, key, storePath)
	if err != token.ErrTokenExhausted {
		t.Errorf("expected ErrTokenExhausted after max uses, got %v", err)
	}
}

// TestVerify_MaxUsesOne_ConcurrentExactlyOneSuccess verifies that 10 goroutines
// racing against a MaxUses=1 token produce exactly 1 success and 9
// ErrTokenExhausted errors (gap #7 / A4-004 cross-process use-counter lock).
func TestVerify_MaxUsesOne_ConcurrentExactlyOneSuccess(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"cap"},
		TTL:          1 * time.Hour,
		MaxUses:      1,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 10
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes, exhausted int

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, verifyErr := token.Verify(jwtStr, nil, key, storePath)
			mu.Lock()
			defer mu.Unlock()
			switch verifyErr { //nolint:staticcheck // QF1003: explicit nil/sentinel comparison is clearest for test assertion
			case nil:
				successes++
			case token.ErrTokenExhausted:
				exhausted++
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Errorf("MaxUses=1 concurrent: expected exactly 1 success, got %d", successes)
	}
	if exhausted != goroutines-1 {
		t.Errorf("MaxUses=1 concurrent: expected %d ErrTokenExhausted, got %d", goroutines-1, exhausted)
	}
}

func TestRevoke_CascadesToChildren(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	_, parent, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"cap"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	childJWT, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"cap"},
		TTL:          1 * time.Hour,
		Parent:       parent.ID,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Revoke parent.
	if err := token.Revoke(parent.ID, storePath); err != nil {
		t.Fatalf("Revoke parent: %v", err)
	}

	// Child should now also be revoked.
	_, err = token.Verify(childJWT, nil, key, storePath)
	if err != token.ErrTokenRevoked {
		t.Errorf("expected child to be revoked, got %v", err)
	}
}

func TestPersistRoundTrip(t *testing.T) {
	key := testSigningKey(t)
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	jwtStr, original, err := token.Mint(token.TokenSpec{
		Actor:        "persist-actor",
		Capabilities: []string{"sentry.report"},
		TTL:          2 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify file was created.
	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("store file not created: %v", err)
	}

	// Load via List and confirm fields.
	toks, err := token.List(token.ListOpts{}, storePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 {
		t.Fatalf("expected 1 token, got %d", len(toks))
	}
	if toks[0].ID != original.ID {
		t.Errorf("ID mismatch: got %q, want %q", toks[0].ID, original.ID)
	}

	// Re-verify after round-trip.
	verified, err := token.Verify(jwtStr, nil, key, storePath)
	if err != nil {
		t.Fatalf("Verify after round-trip: %v", err)
	}
	if verified.Actor != "persist-actor" {
		t.Errorf("actor after round-trip: %q", verified.Actor)
	}
}

func TestHasCapability(t *testing.T) {
	cases := []struct {
		name         string
		capabilities []string
		query        string
		want         bool
	}{
		{
			name:         "exact match",
			capabilities: []string{"openai.chat_completion"},
			query:        "openai.chat_completion",
			want:         true,
		},
		{
			name:         "wildcard matches specific capability",
			capabilities: []string{"openai.*"},
			query:        "openai.chat_completion",
			want:         true,
		},
		{
			name:         "wildcard does not match different provider",
			capabilities: []string{"openai.*"},
			query:        "anthropic.chat_completion",
			want:         false,
		},
		{
			name:         "wildcard does not match bare provider name without dot",
			capabilities: []string{"openai.*"},
			query:        "openai",
			want:         false,
		},
		{
			name:         "no matching capability",
			capabilities: []string{"anthropic.summarize"},
			query:        "openai.chat_completion",
			want:         false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok := &token.Token{Capabilities: tc.capabilities}
			got := token.HasCapability(tok, tc.query)
			if got != tc.want {
				t.Errorf("HasCapability(%v, %q) = %v, want %v", tc.capabilities, tc.query, got, tc.want)
			}
		})
	}
}

func TestList_FilterOptions(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)

	_, _, err := token.Mint(token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"cap"},
		TTL:          1 * time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	toks, err := token.List(token.ListOpts{}, storePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(toks) != 1 {
		t.Errorf("expected 1 active token, got %d", len(toks))
	}

	// With IncludeExpired false, expired tokens should be excluded.
	toksAll, err := token.List(token.ListOpts{IncludeExpired: true, IncludeRevoked: true}, storePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(toksAll) < len(toks) {
		t.Error("IncludeAll should return at least as many tokens")
	}
}
