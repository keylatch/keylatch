package llmcontext_test

// ticket_test.go — EPIC-05 Task 2
//
// Tests for IssueTicket and VerifyTicket.

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeSigningKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	return key
}

// TestIssueTicket_RoundTrip verifies that a ticket can be issued and verified.
func TestIssueTicket_RoundTrip(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)

	raw, err := llmcontext.IssueTicket("session-123", "claude-code", key)
	require.NoError(t, err)
	require.NotEmpty(t, raw)

	tick, err := llmcontext.VerifyTicket(raw, key)
	require.NoError(t, err)
	assert.Equal(t, "session-123", tick.SessionID)
	assert.Equal(t, "claude-code", tick.Agent)
	assert.WithinDuration(t, time.Now(), tick.IssuedAt, 5*time.Second)
	assert.WithinDuration(t, time.Now().Add(5*time.Minute), tick.ExpiresAt, 5*time.Second)
}

// TestIssueTicket_EmptySessionID returns ErrTicketInvalid.
func TestIssueTicket_EmptySessionID(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)
	_, err := llmcontext.IssueTicket("", "agent", key)
	require.Error(t, err)
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}

// TestIssueTicket_ShortKey returns ErrTicketInvalid.
func TestIssueTicket_ShortKey(t *testing.T) {
	t.Parallel()
	_, err := llmcontext.IssueTicket("sid", "agent", []byte("short"))
	require.Error(t, err)
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}

// TestVerifyTicket_WrongKey rejects tokens signed with a different key.
func TestVerifyTicket_WrongKey(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)
	wrongKey := makeSigningKey(t)

	raw, err := llmcontext.IssueTicket("session-456", "cursor", key)
	require.NoError(t, err)

	_, err = llmcontext.VerifyTicket(raw, wrongKey)
	require.Error(t, err)
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}

// TestVerifyTicket_AlgNone rejects alg:none tokens (a common JWT attack).
func TestVerifyTicket_AlgNone(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)
	// Construct a minimal alg:none token. The signature is empty.
	// header: {"alg":"none","typ":"JWT"} → eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
	algNoneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJrZXlsYXRjaGQiLCJzdWIiOiJsbG0tc2Vzc2lvbiIsInNpZCI6IngiLCJleHAiOjk5OTk5OTk5OTl9."

	_, err := llmcontext.VerifyTicket(algNoneToken, key)
	require.Error(t, err, "alg:none token must be rejected")
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}

// TestVerifyTicket_Expired rejects an expired token.
func TestVerifyTicket_Expired(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32) // zero key for repeatability

	// Build a token with exp=1 (Unix epoch+1 — always expired).
	claims := jwt.MapClaims{
		"iss": "keylatchd",
		"sub": "llm-session",
		"sid": "s",
		"exp": int64(1),
		"iat": int64(0),
	}
	expiredToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	require.NoError(t, err)

	_, err = llmcontext.VerifyTicket(expiredToken, key)
	require.Error(t, err)
	assert.ErrorIs(t, err, llmcontext.ErrTicketExpired,
		"expired token must return ErrTicketExpired, got: %v", err)
}

// TestVerifyTicket_ShortKey rejects calls with insufficient key length.
func TestVerifyTicket_ShortKey(t *testing.T) {
	t.Parallel()
	_, err := llmcontext.VerifyTicket("any.token.here", []byte("tooshort"))
	require.Error(t, err)
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}

// TestVerifyTicket_Malformed rejects a garbage string.
func TestVerifyTicket_Malformed(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)
	_, err := llmcontext.VerifyTicket("not-a-jwt", key)
	require.Error(t, err)
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}

// TestIssueTicket_TTL verifies the issued ticket expires within 5 minutes.
func TestIssueTicket_TTL(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)
	raw, err := llmcontext.IssueTicket("ttl-test", "agent", key)
	require.NoError(t, err)

	tick, err := llmcontext.VerifyTicket(raw, key)
	require.NoError(t, err)

	ttl := tick.ExpiresAt.Sub(tick.IssuedAt)
	assert.LessOrEqual(t, ttl, 5*time.Minute,
		"ticket TTL must be ≤ 5 minutes (EPIC-05 requirement)")
	assert.Greater(t, ttl, time.Duration(0),
		"ticket TTL must be positive")
}
