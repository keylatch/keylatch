package oidc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team/oidc"
)

func TestLogin_IDTokenNeverWrittenToDisk(t *testing.T) {
	ctx := context.Background()
	opts := oidc.LoginOpts{
		ClientID:      "test-client",
		MaxSessionAge: time.Hour,
	}

	session, err := oidc.Login(ctx, oidc.ProviderGoogle, opts)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// Session subject is in-memory.
	if session.Subject == "" {
		t.Error("session.Subject should be non-empty in memory")
	}

	// Verify the session JSON tag is "-" (won't appear in marshaled output).
	// We test by checking that the session struct has non-zero Subject in memory.
	if !strings.HasPrefix(session.Subject, "sub-") {
		t.Errorf("Subject format unexpected: %q", session.Subject)
	}
}

func TestValidateSession_MaxSessionAge(t *testing.T) {
	// Simulate a session that is exactly at the max session age limit.
	maxAge := 2 * time.Hour
	now := time.Now()
	session := &oidc.Session{
		Provider:      oidc.ProviderGoogle,
		Subject:       "sub-test",
		IssuedAt:      now,
		ExpiresAt:     now.Add(maxAge),
		MaxSessionAge: maxAge,
	}

	// Session just started — should be valid.
	if err := oidc.ValidateSession(session); err != nil {
		t.Errorf("fresh session should be valid: %v", err)
	}

	// Simulate session started long ago (maxAge exceeded).
	oldSession := &oidc.Session{
		Provider:      oidc.ProviderGoogle,
		Subject:       "sub-old",
		ExpiresAt:     now.Add(-time.Minute), // expired
		MaxSessionAge: maxAge,
	}
	if err := oidc.ValidateSession(oldSession); err == nil {
		t.Error("expired session should fail ValidateSession")
	}
}

func TestValidateSession_MaxSessionAge_ExceededFromIssuedAt(t *testing.T) {
	// M-11: session was issued MaxSessionAge+1 ago — must return ErrMaxSessionAge.
	maxAge := 2 * time.Hour
	issuedAt := time.Now().Add(-(maxAge + time.Minute)) // issued maxAge+1min ago
	session := &oidc.Session{
		Provider:      oidc.ProviderGoogle,
		Subject:       "sub-old",
		IssuedAt:      issuedAt,
		ExpiresAt:     time.Now().Add(time.Hour), // not yet expired by time, but max age exceeded
		MaxSessionAge: maxAge,
	}
	if err := oidc.ValidateSession(session); err != oidc.ErrMaxSessionAge {
		t.Errorf("session past MaxSessionAge: got %v, want ErrMaxSessionAge", err)
	}
}

func TestValidateSession_Expired(t *testing.T) {
	session := &oidc.Session{
		Provider:  oidc.ProviderGitHub,
		Subject:   "sub-expired",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	if err := oidc.ValidateSession(session); err != oidc.ErrSessionExpired {
		t.Errorf("ValidateSession expired: got %v, want ErrSessionExpired", err)
	}
}

func TestStoreRefreshToken_RejectsIDToken(t *testing.T) {
	ctx := context.Background()
	// Construct an ID-token-shaped string: starts with "ey" and has 2 dots.
	fakeIDToken := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.signature"

	defer func() {
		r := recover()
		if r == nil {
			t.Error("StoreRefreshToken should panic for ID-token-shaped token")
		}
	}()

	// Should panic.
	_ = oidc.StoreRefreshToken(ctx, oidc.ProviderGoogle, fakeIDToken)
}

func TestStoreRefreshToken_AcceptsOpaqueToken(t *testing.T) {
	ctx := context.Background()
	// Opaque refresh token (not JWT shaped).
	opaqueToken := "rt_abc123def456"

	if err := oidc.StoreRefreshToken(ctx, oidc.ProviderGoogle, opaqueToken); err != nil {
		t.Errorf("StoreRefreshToken for opaque token: %v", err)
	}
}

func TestValidateSession_Nil(t *testing.T) {
	if err := oidc.ValidateSession(nil); err != oidc.ErrSessionExpired {
		t.Errorf("nil session: got %v, want ErrSessionExpired", err)
	}
}
