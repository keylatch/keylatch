package llmcontext

// ticket.go
//
// Signed session ticket for tamper-resistant LLM session detection.
//
// The ticket is a short-lived HS256-signed JWT that the keylatchd daemon issues
// when a new LLM session is registered via POST /v1/llm-session. The CLI (and
// any future IDE extension) can present the ticket in the KEYLATCH_LLM_TICKET
// environment variable; IsLLMSession verifies it against the daemon's signing key.
//
// Fail-closed contract: any error during ticket verification (malformed token,
// wrong signature, expired, alg:none attempt) causes verification to fail, which
// means the caller treats the result as an unverified signal and falls through to
// the IPC or env-var check chain. If those are also ambiguous, IsLLMSession
// returns true (assume LLM session) — never false on ambiguity.

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// ticketTTL is the maximum lifetime of a session ticket.
	// Requirement: TTL must be ≤ 5 minutes.
	ticketTTL = 5 * time.Minute

	// ticketIssuer is embedded in the JWT "iss" claim so forged tokens from
	// other services can be detected during verification.
	ticketIssuer = "keylatchd"

	// ticketSubject is the JWT "sub" claim — all LLM session tickets share this.
	ticketSubject = "llm-session"
)

// ErrTicketInvalid is returned by VerifyTicket when the raw token is structurally
// malformed, uses a disallowed algorithm, or has been tampered with.
var ErrTicketInvalid = errors.New("llm session ticket invalid")

// ErrTicketExpired is returned by VerifyTicket when the ticket's expiry has passed.
var ErrTicketExpired = errors.New("llm session ticket expired")

// Ticket holds the verified claims from a session ticket JWT.
type Ticket struct {
	// SessionID is the opaque identifier for this LLM session,
	// assigned by keylatchd at registration time.
	SessionID string

	// Agent is the IDE/tool that created the session (e.g. "claude-code").
	// May be empty for manually registered sessions.
	Agent string

	// IssuedAt is the time the ticket was signed.
	IssuedAt time.Time

	// ExpiresAt is the time after which the ticket must be rejected.
	ExpiresAt time.Time
}

// llmTicketClaims is the jwt.Claims implementation used for round-tripping.
type llmTicketClaims struct {
	jwt.RegisteredClaims
	SessionID string `json:"sid"`
	Agent     string `json:"agent,omitempty"`
}

// IssueTicket creates a new HS256-signed JWT for an LLM session.
//
// signingKey must be at least 32 bytes. The ticket is valid for at most ticketTTL
// (5 minutes). Callers should store the returned raw string in KEYLATCH_LLM_TICKET
// or pass it to the daemon for registration.
func IssueTicket(sessionID, agent string, signingKey []byte) (raw string, err error) {
	if len(signingKey) < 32 {
		return "", fmt.Errorf("%w: signing key must be at least 32 bytes", ErrTicketInvalid)
	}
	if sessionID == "" {
		return "", fmt.Errorf("%w: sessionID must not be empty", ErrTicketInvalid)
	}

	now := time.Now()
	exp := now.Add(ticketTTL)

	claims := llmTicketClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ticketIssuer,
			Subject:   ticketSubject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		SessionID: sessionID,
		Agent:     agent,
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err = tok.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("%w: signing: %w", ErrTicketInvalid, err)
	}
	return raw, nil
}

// VerifyTicket parses and validates raw against signingKey.
//
// Fail-closed: any error returns a zero Ticket and a non-nil error.
// Algorithm: only HS256 is accepted — "alg:none" and asymmetric algorithms are
// explicitly rejected by the jwt.WithValidMethods option.
//
// Error types:
//   - ErrTicketExpired — the "exp" claim has passed (or is missing)
//   - ErrTicketInvalid — all other failure modes (bad sig, alg:none, malformed)
func VerifyTicket(raw string, signingKey []byte) (Ticket, error) {
	if len(signingKey) < 32 {
		return Ticket{}, fmt.Errorf("%w: signing key must be at least 32 bytes", ErrTicketInvalid)
	}

	var claims llmTicketClaims
	tok, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (interface{}, error) {
		return signingKey, nil
	},
		// Allowlist only HS256 — explicitly rejects alg:none and RSA/ECDSA.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithIssuer(ticketIssuer),
		jwt.WithSubject(ticketSubject),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		// Distinguish expiry from other failures so callers can log differently.
		if errors.Is(err, jwt.ErrTokenExpired) {
			return Ticket{}, fmt.Errorf("%w: %v", ErrTicketExpired, err)
		}
		return Ticket{}, fmt.Errorf("%w: %v", ErrTicketInvalid, err)
	}

	if !tok.Valid {
		return Ticket{}, ErrTicketInvalid
	}

	exp := time.Time{}
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	iat := time.Time{}
	if claims.IssuedAt != nil {
		iat = claims.IssuedAt.Time
	}

	return Ticket{
		SessionID: claims.SessionID,
		Agent:     claims.Agent,
		IssuedAt:  iat,
		ExpiresAt: exp,
	}, nil
}
