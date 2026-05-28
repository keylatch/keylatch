// Package expiry provides pure computation functions for secret expiry status.
// No backend IO, no encryption, no CLI coupling.
package expiry

import (
	"math"
	"time"

	"github.com/keylatch/keylatch/internal/vault/meta"
)

// DefaultWarnDays is the number of days before expiry at which Status returns
// "warn". Used when the caller passes warnDays <= 0.
const DefaultWarnDays = 30

// IsExpired reports whether the secret has passed its expiry time.
// Returns false if ExpiresAt is nil (no expiry configured).
func IsExpired(m meta.Meta, now time.Time) bool {
	if m.ExpiresAt == nil {
		return false
	}
	return !now.Before(*m.ExpiresAt)
}

// DaysRemaining returns the number of whole days until expiry (truncated toward zero).
// Returns math.MaxInt32 if ExpiresAt is nil. Returns a negative value if already expired.
func DaysRemaining(m meta.Meta, now time.Time) int {
	if m.ExpiresAt == nil {
		return math.MaxInt32
	}
	return int(m.ExpiresAt.Sub(now).Hours() / 24)
}

// Status returns a human-readable expiry status string:
//   - "expired" — the secret is past ExpiresAt
//   - "warn"    — within warnDays days of expiry (or DefaultWarnDays if warnDays <= 0)
//   - "ok"      — not expiring soon
func Status(m meta.Meta, now time.Time, warnDays int) string {
	if warnDays <= 0 {
		warnDays = DefaultWarnDays
	}
	if IsExpired(m, now) {
		return "expired"
	}
	if DaysRemaining(m, now) <= warnDays {
		return "warn"
	}
	return "ok"
}
