package llmcontext

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TicketTTL is the lifetime of a session ticket issued by `keylatch launch`.
const TicketTTL = 12 * time.Hour

const (
	ticketIssuer  = "keylatch-launch"
	ticketSubject = "agent-session"
)

// ErrTicketInvalid is returned for a malformed, tampered or wrongly signed ticket.
var ErrTicketInvalid = errors.New("session ticket invalid")

// ErrTicketExpired is returned when the ticket's expiry has passed.
var ErrTicketExpired = errors.New("session ticket expired")

// Ticket is a signed statement that the process tree below one supervising
// process is an agent session.
type Ticket struct {
	SessionID string
	Harness   string
	// PID and ProcessStart identify the supervising process; the start time
	// guards against PID reuse.
	PID          int
	ProcessStart uint64
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

type ticketClaims struct {
	jwt.RegisteredClaims
	SessionID    string `json:"sid"`
	Harness      string `json:"harness,omitempty"`
	PID          int    `json:"pid"`
	ProcessStart uint64 `json:"pst"`
}

// IssueTicket signs t with HS256. IssuedAt and ExpiresAt are set from the
// current time and TicketTTL.
func IssueTicket(t Ticket, signingKey []byte) (string, error) {
	if len(signingKey) < 32 {
		return "", fmt.Errorf("%w: signing key must be at least 32 bytes", ErrTicketInvalid)
	}
	if t.SessionID == "" || t.PID <= 0 || t.ProcessStart == 0 {
		return "", fmt.Errorf("%w: session ID, PID and process start time are required", ErrTicketInvalid)
	}
	now := time.Now()
	claims := ticketClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ticketIssuer,
			Subject:   ticketSubject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(TicketTTL)),
		},
		SessionID:    t.SessionID,
		Harness:      t.Harness,
		PID:          t.PID,
		ProcessStart: t.ProcessStart,
	}
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("%w: signing: %w", ErrTicketInvalid, err)
	}
	return raw, nil
}

// VerifyTicket checks raw's signature (HS256 only), issuer, subject and
// expiry. It does not check the process binding.
func VerifyTicket(raw string, signingKey []byte) (Ticket, error) {
	if len(signingKey) < 32 {
		return Ticket{}, fmt.Errorf("%w: signing key must be at least 32 bytes", ErrTicketInvalid)
	}
	var claims ticketClaims
	tok, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (interface{}, error) {
		return signingKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithIssuer(ticketIssuer),
		jwt.WithSubject(ticketSubject),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return Ticket{}, fmt.Errorf("%w: %v", ErrTicketExpired, err)
		}
		return Ticket{}, fmt.Errorf("%w: %v", ErrTicketInvalid, err)
	}
	if !tok.Valid || claims.SessionID == "" || claims.PID <= 0 || claims.ProcessStart == 0 {
		return Ticket{}, ErrTicketInvalid
	}
	return Ticket{
		SessionID:    claims.SessionID,
		Harness:      claims.Harness,
		PID:          claims.PID,
		ProcessStart: claims.ProcessStart,
		IssuedAt:     claims.IssuedAt.Time,
		ExpiresAt:    claims.ExpiresAt.Time,
	}, nil
}
