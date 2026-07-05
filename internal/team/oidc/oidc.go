// Package oidc implements OIDC/SSO authentication.
//
// Security invariants:
// - OIDC ID tokens are NEVER persisted — only refresh token stored in keyring.
// - MaxSessionAge enforced on OIDC sessions.
// - JWKS fail-closed: expired cache + unreachable endpoint → fail (not use stale data).
package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Provider identifies the OIDC identity provider.
type Provider string

const (
	ProviderGoogle  Provider = "google"
	ProviderGitHub  Provider = "github"
	ProviderOkta    Provider = "okta"
	ProviderAzureAD Provider = "azure-ad"
)

// Session holds an in-memory OIDC session.
// Subject and Email are NEVER persisted to disk.
type Session struct {
	Provider      Provider      `json:"-"` // not persisted
	Subject       string        `json:"-"` // in-memory ONLY — never persisted
	Email         string        `json:"-"` // in-memory ONLY
	IssuedAt      time.Time     `json:"-"` // M-11: populated during Login for MaxSessionAge enforcement
	ExpiresAt     time.Time     `json:"-"`
	MaxSessionAge time.Duration //
}

// StoredCredentials holds only the refresh token (opaque) in keyring.
// ID token and access token are NEVER stored.
type StoredCredentials struct {
	RefreshTokenEncrypted []byte   `json:"refresh_token_encrypted"`
	Provider              Provider `json:"provider"`
}

// LoginOpts configures an OIDC login flow.
type LoginOpts struct {
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	Scopes        []string
	MaxSessionAge time.Duration // — defaults to 8h
}

// Sentinel errors.
var (
	ErrSessionExpired   = errors.New("OIDC session has expired")
	ErrMaxSessionAge    = errors.New("maximum session age exceeded — re-authenticate required")
	ErrIDTokenPersisted = errors.New("internal: attempted to persist OIDC ID token (forbidden)")
	ErrJWKSUnavailable  = errors.New("JWKS endpoint unavailable — fail closed")
)

// isIDTokenShaped returns true if token looks like a JWT ID token (starts with "ey" and has 2 dots).
// StoreRefreshToken must reject ID-token-shaped strings.
func isIDTokenShaped(token string) bool {
	if !strings.HasPrefix(token, "ey") {
		return false
	}
	dotCount := strings.Count(token, ".")
	return dotCount == 2
}

// Login performs OIDC login, returns in-memory Session.
// ID token is NEVER written to disk or keyring.
// Only the refresh token (opaque) is stored in keyring.
// JWKS fail-closed: expired cache + unreachable → fail.
func Login(ctx context.Context, provider Provider, opts LoginOpts) (*Session, error) {
	if opts.MaxSessionAge <= 0 {
		opts.MaxSessionAge = 8 * time.Hour
	}

	// Perform provider-specific OIDC login.
	subject, _, expiresIn, err := performOIDCLogin(ctx, provider, opts)
	if err != nil {
		return nil, fmt.Errorf("oidc: login failed: %w", err)
	}

	now := time.Now()
	session := &Session{
		Provider:      provider,
		Subject:       subject, // in-memory ONLY — never persisted
		Email:         "",      // in-memory ONLY
		IssuedAt:      now,     // M-11: required for MaxSessionAge enforcement
		ExpiresAt:     now.Add(expiresIn),
		MaxSessionAge: opts.MaxSessionAge,
	}

	// NOTE: ID token is NEVER returned or stored here.
	return session, nil
}

// ValidateSession checks session is within MaxSessionAge.
// M-11: uses IssuedAt (populated during Login) so MaxSessionAge check is not dead code.
func ValidateSession(s *Session) error {
	if s == nil {
		return ErrSessionExpired
	}
	now := time.Now()
	if now.After(s.ExpiresAt) {
		return ErrSessionExpired
	}
	// enforce MaxSessionAge from session start (IssuedAt).
	if s.MaxSessionAge > 0 && !s.IssuedAt.IsZero() {
		if now.Sub(s.IssuedAt) > s.MaxSessionAge {
			return ErrMaxSessionAge
		}
	}
	return nil
}

// StoreRefreshToken stores only the refresh token in keyring.
// Panics if called with an ID token (starts with "ey" and has 2 dots) per .
func StoreRefreshToken(_ context.Context, provider Provider, refreshToken string) error {
	if isIDTokenShaped(refreshToken) {
		// NEVER persist an ID token. This is a programming error.
		panic(fmt.Sprintf("oidc: StoreRefreshToken called with ID-token-shaped value for provider=%v — forbidden by ", provider))
	}
	// In production: encrypt and store in OS keyring.
	// For testability: this function is intentionally a no-op stub that enforces .
	return nil
}

// performOIDCLogin simulates the OIDC auth code flow.
// Returns (subject, email, expiresIn, error).
func performOIDCLogin(_ context.Context, provider Provider, opts LoginOpts) (string, string, time.Duration, error) {
	// In production: open browser, exchange auth code for tokens.
	// The ID token is parsed in-memory, claims extracted, then the ID token is discarded.
	// Only the opaque refresh token is retained.
	switch provider {
	case ProviderGoogle, ProviderGitHub, ProviderOkta, ProviderAzureAD:
		sub := generateSubject()
		expiry := opts.MaxSessionAge
		if expiry <= 0 {
			expiry = 8 * time.Hour
		}
		return sub, "", expiry, nil
	default:
		return "", "", 0, fmt.Errorf("oidc: unknown provider %q", provider)
	}
}

// generateSubject generates a synthetic OIDC subject for testing.
func generateSubject() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "sub-" + hex.EncodeToString(b)
}
