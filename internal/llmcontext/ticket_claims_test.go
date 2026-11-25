package llmcontext_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gdSign(t *testing.T, method jwt.SigningMethod, claims jwt.MapClaims, key []byte) string {
	t.Helper()
	raw, err := jwt.NewWithClaims(method, claims).SignedString(key)
	require.NoError(t, err)
	return raw
}

func TestVerifyTicket_RejectsForeignClaims(t *testing.T) {
	key := makeSigningKey(t)
	now := time.Now()
	base := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "keylatch-launch",
			"sub": "agent-session",
			"iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(),
			"sid": "s1",
			"pid": 42,
			"pst": 7,
		}
	}

	ok := gdSign(t, jwt.SigningMethodHS256, base(), key)
	tk, err := llmcontext.VerifyTicket(ok, key)
	require.NoError(t, err)
	assert.Equal(t, "s1", tk.SessionID)
	assert.Equal(t, 42, tk.PID)
	assert.Equal(t, uint64(7), tk.ProcessStart)
	assert.Empty(t, tk.Harness)

	cases := map[string]func() string{
		"wrong issuer": func() string {
			c := base()
			c["iss"] = "someone-else"
			return gdSign(t, jwt.SigningMethodHS256, c, key)
		},
		"wrong subject": func() string {
			c := base()
			c["sub"] = "admin"
			return gdSign(t, jwt.SigningMethodHS256, c, key)
		},
		"issued in the future": func() string {
			c := base()
			c["iat"] = now.Add(time.Hour).Unix()
			c["exp"] = now.Add(2 * time.Hour).Unix()
			return gdSign(t, jwt.SigningMethodHS256, c, key)
		},
		"HS512 not allowlisted": func() string {
			return gdSign(t, jwt.SigningMethodHS512, base(), key)
		},
	}
	for name, mk := range cases {
		got, err := llmcontext.VerifyTicket(mk(), key)
		require.Error(t, err, name)
		assert.True(t, errors.Is(err, llmcontext.ErrTicketInvalid), "%s: %v", name, err)
		assert.False(t, errors.Is(err, llmcontext.ErrTicketExpired), name)
		assert.Equal(t, llmcontext.Ticket{}, got, name)
	}

	for _, drop := range []string{"sid", "pid", "pst"} {
		c := base()
		delete(c, drop)
		_, err = llmcontext.VerifyTicket(gdSign(t, jwt.SigningMethodHS256, c, key), key)
		require.ErrorIs(t, err, llmcontext.ErrTicketInvalid, "missing %s", drop)
	}

	noExp := base()
	delete(noExp, "exp")
	_, err = llmcontext.VerifyTicket(gdSign(t, jwt.SigningMethodHS256, noExp, key), key)
	require.Error(t, err, "a ticket without expiry must be rejected")
}

func TestVerifyTicket_TamperedPayload(t *testing.T) {
	key := makeSigningKey(t)
	raw, err := llmcontext.IssueTicket(llmcontext.Ticket{SessionID: "sess", Harness: "cursor", PID: 42, ProcessStart: 7}, key)
	require.NoError(t, err)

	other, err := llmcontext.IssueTicket(llmcontext.Ticket{SessionID: "other", Harness: "cursor", PID: 42, ProcessStart: 7}, key)
	require.NoError(t, err)
	parts := strings.Split(raw, ".")
	otherParts := strings.Split(other, ".")
	forged := parts[0] + "." + otherParts[1] + "." + parts[2]

	_, err = llmcontext.VerifyTicket(forged, key)
	require.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
}
