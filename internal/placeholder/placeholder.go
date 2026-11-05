// Package placeholder delivers a credential to a child process as a worthless
// stand-in. The child holds a placeholder in the variable its tool reads; an
// intercepting proxy owned by the daemon swaps in the real value only in the
// request positions, and only toward the hosts, that the provider template
// binds the credential to. A placeholder seen anywhere else suspends the
// session.
package placeholder

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/registry"
)

const (
	// marker starts the random part of every placeholder.
	marker = "klph_"
	// tokenLen is the length of 128 random bits in unpadded base32.
	tokenLen = 26

	defaultTTL     = 15 * time.Minute
	maxTTL         = 8 * time.Hour
	defaultMaxUses = 500
)

// Resolver reads a credential from the backing store. The proxy calls it at
// the moment a request needs the value and never caches the result.
type Resolver interface {
	Resolve(ctx context.Context, connection, field string) ([]byte, error)
}

// Config configures a Manager.
type Config struct {
	Resolver Resolver
	// Audit receives every decision. Sessions are refused without it because
	// an unaudited substitution would break the audit invariant.
	Audit audit.Emitter
	// TTL bounds a session and its placeholders; zero selects fifteen minutes.
	TTL time.Duration
	// MaxUses bounds the requests a placeholder may be substituted into; zero
	// selects 500.
	MaxUses  int
	Upstream Upstream
}

var (
	errNoResolver = errors.New("placeholder: no credential resolver is configured")
	errNoAudit    = errors.New("placeholder: no audit log is configured")
	// ErrNoBinding is returned when a template declares no slots to substitute.
	ErrNoBinding = errors.New("placeholder: the connection declares no host bindings")
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newValue returns a fresh placeholder that satisfies the template's shape.
func newValue(shape registry.PlaceholderShape) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("placeholder: random source: %w", err)
	}
	return shape.Wrap(marker + strings.ToLower(b32.EncodeToString(raw[:]))), nil
}

func randomID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("placeholder: random source: %w", err)
	}
	return strings.ToLower(b32.EncodeToString(raw[:])), nil
}
