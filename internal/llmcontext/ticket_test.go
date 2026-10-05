package llmcontext_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

func sampleTicket() llmcontext.Ticket {
	return llmcontext.Ticket{SessionID: "session-123", Harness: "claude-code", PID: 4242, ProcessStart: 987654321}
}

func TestIssueTicket_RoundTrip(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)

	raw, err := llmcontext.IssueTicket(sampleTicket(), key)
	require.NoError(t, err)

	got, err := llmcontext.VerifyTicket(raw, key)
	require.NoError(t, err)
	assert.Equal(t, "session-123", got.SessionID)
	assert.Equal(t, "claude-code", got.Harness)
	assert.Equal(t, 4242, got.PID)
	assert.Equal(t, uint64(987654321), got.ProcessStart)
	assert.WithinDuration(t, time.Now(), got.IssuedAt, 5*time.Second)
	assert.WithinDuration(t, time.Now().Add(llmcontext.TicketTTL), got.ExpiresAt, 5*time.Second)
	assert.Equal(t, 12*time.Hour, llmcontext.TicketTTL)
}

func TestIssueTicket_RequiresBinding(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)
	for name, mutate := range map[string]func(*llmcontext.Ticket){
		"session": func(tk *llmcontext.Ticket) { tk.SessionID = "" },
		"pid":     func(tk *llmcontext.Ticket) { tk.PID = 0 },
		"start":   func(tk *llmcontext.Ticket) { tk.ProcessStart = 0 },
	} {
		tk := sampleTicket()
		mutate(&tk)
		_, err := llmcontext.IssueTicket(tk, key)
		assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid, name)
	}
	_, err := llmcontext.IssueTicket(sampleTicket(), []byte("short"))
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}

func TestVerifyTicket_WrongKey(t *testing.T) {
	t.Parallel()
	raw, err := llmcontext.IssueTicket(sampleTicket(), makeSigningKey(t))
	require.NoError(t, err)
	_, err = llmcontext.VerifyTicket(raw, makeSigningKey(t))
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}

func TestVerifyTicket_AlgNone(t *testing.T) {
	t.Parallel()
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	token := enc(map[string]string{"alg": "none", "typ": "JWT"}) + "." +
		enc(map[string]any{"iss": "keylatch-launch", "sub": "agent-session", "sid": "x", "pid": 1, "pst": 1, "exp": 9999999999, "iat": 1}) + "."
	_, err := llmcontext.VerifyTicket(token, makeSigningKey(t))
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}

func TestVerifyTicket_Expired(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)
	claims := jwt.MapClaims{"iss": "keylatch-launch", "sub": "agent-session", "sid": "s", "pid": 1, "pst": 1, "exp": int64(1), "iat": int64(0)}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	require.NoError(t, err)
	_, err = llmcontext.VerifyTicket(raw, key)
	assert.ErrorIs(t, err, llmcontext.ErrTicketExpired)
}

func TestVerifyTicket_RejectsOtherIssuersAndMissingBinding(t *testing.T) {
	t.Parallel()
	key := makeSigningKey(t)
	exp := time.Now().Add(time.Hour).Unix()
	for name, claims := range map[string]jwt.MapClaims{
		"issuer":  {"iss": "keylatchd", "sub": "agent-session", "sid": "s", "pid": 1, "pst": 1, "exp": exp, "iat": 1},
		"subject": {"iss": "keylatch-launch", "sub": "llm-session", "sid": "s", "pid": 1, "pst": 1, "exp": exp, "iat": 1},
		"pid":     {"iss": "keylatch-launch", "sub": "agent-session", "sid": "s", "pst": 1, "exp": exp, "iat": 1},
	} {
		raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
		require.NoError(t, err)
		_, err = llmcontext.VerifyTicket(raw, key)
		assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid, name)
	}
}

func TestVerifyTicket_MalformedAndShortKey(t *testing.T) {
	t.Parallel()
	_, err := llmcontext.VerifyTicket("not-a-jwt", makeSigningKey(t))
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
	_, err = llmcontext.VerifyTicket("a.b.c", []byte("short"))
	assert.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}
