package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scKey() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i * 7)
	}
	return k
}

func scMAC(key []byte, data string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return hex.EncodeToString(m.Sum(nil))
}

func TestConsumeBootstrap_ExpiredSessionRejected(t *testing.T) {
	s, err := New(scKey())
	if err != nil {
		t.Fatal(err)
	}
	s.expiresAt = time.Now().Add(-time.Second)
	if _, err := s.ConsumeBootstrap(s.token, scMAC(scKey(), s.token)); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
	if s.consumed {
		t.Fatal("expired bootstrap marked consumed")
	}
}

func TestConsumeBootstrap_ValidMACForOtherTokenRejected(t *testing.T) {
	key := scKey()
	s, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("ab", 32)
	if _, err := s.ConsumeBootstrap(other, scMAC(key, other)); !errors.Is(err, ErrInvalidHMAC) {
		t.Fatalf("want ErrInvalidHMAC, got %v", err)
	}
	if s.consumed {
		t.Fatal("foreign token consumed the bootstrap")
	}
	id, err := s.ConsumeBootstrap(s.token, scMAC(key, s.token))
	if err != nil || id != s.id {
		t.Fatalf("legit consume after rejected attempt: %q %v", id, err)
	}
}

func TestValidateRequest_ExpiredSessionRejectsValidCookie(t *testing.T) {
	s, err := New(scKey())
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: CookieName(), Value: s.id})
	if err := s.ValidateRequest(r); err != nil {
		t.Fatalf("fresh session: %v", err)
	}
	s.expiresAt = time.Now().Add(-time.Second)
	if err := s.ValidateRequest(r); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestURL_MACVerifiesUnderSigningKey(t *testing.T) {
	key := scKey()
	s, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	u := s.URL("http://127.0.0.1:1")
	if !strings.Contains(u, "b="+s.token) || !strings.Contains(u, "mac="+scMAC(key, s.token)) {
		t.Fatalf("bootstrap URL %q", u)
	}
	if strings.Contains(u, hex.EncodeToString(key)) {
		t.Fatal("signing key leaked into URL")
	}
}
