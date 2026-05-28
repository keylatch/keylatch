// Package breakglass implements Phase 12 break-glass emergency access.
//
// Security invariants:
//   - S12-10: Break-glass blocked during LLM sessions (except draft exception per spec §6.7).
//   - FIND2-016: Rate-limiting per member: max 3 opens per 24h.
//   - FIND2-021: Cooling period enforced: min 1h between close and next open.
//   - Counters backed by files in ~/.keylatch/team/breakglass/ — survive restarts.
//   - M-1: File-level locking prevents TOCTOU races on counter files.
//   - N-5: Corrupt counter file returns error instead of silently resetting.
//   - Reason IS stored in audit (loud by design — spec §6.7).
package breakglass

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/keylatch/keylatch/internal/team"
)

// BGStatus describes the state of a break-glass request.
type BGStatus string

const (
	BGOpen   BGStatus = "open"
	BGClosed BGStatus = "closed"
)

// BreakGlassRequest is a break-glass session record.
type BreakGlassRequest struct {
	ID         string     `json:"id"`
	MemberHMAC string     `json:"member_hmac"`
	Reason     string     `json:"reason"` // loud by design — spec §6.7
	Status     BGStatus   `json:"status"`
	OpenedAt   time.Time  `json:"opened_at"`
	ClosedAt   *time.Time `json:"closed_at,omitempty"`
	AuditRef   string     `json:"audit_ref"`
}

// Sentinel errors.
var (
	ErrRateLimitExceeded = errors.New("break-glass rate limit exceeded for this member")
	ErrCoolingPeriod     = errors.New("break-glass cooling period has not elapsed")
	ErrLLMSessionBlocked = errors.New("break-glass blocked during LLM session")
)

// llmSessionKey is the context key for marking LLM sessions.
type llmSessionKey struct{}

// WithLLMSession returns a context marked as an LLM session.
func WithLLMSession(ctx context.Context) context.Context {
	return context.WithValue(ctx, llmSessionKey{}, true)
}

// isLLMSession returns true if the context carries an LLM session marker.
func isLLMSession(ctx context.Context) bool {
	v, _ := ctx.Value(llmSessionKey{}).(bool)
	return v
}

// breakglassDir returns the directory for break-glass counter files.
func breakglassDir() string {
	if v := os.Getenv("KEYLATCH_TEAM_DIR"); v != "" {
		return filepath.Join(v, "breakglass")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".keylatch", "team", "breakglass")
	}
	return filepath.Join(home, ".keylatch", "team", "breakglass")
}

// memberCounterPath returns the file path for a member's break-glass counter.
func memberCounterPath(member team.Member) string {
	return filepath.Join(breakglassDir(), "counter-"+member.HMAC+".json")
}

// memberCounter tracks rate limiting for a single member.
type memberCounter struct {
	Opens     []time.Time `json:"opens"`                // timestamps of opens in last 24h
	LastClose *time.Time  `json:"last_close,omitempty"` // time of most recent close
}

// withCounterLock acquires an exclusive file lock on path+".lock", calls fn with the
// loaded counter, then saves and releases. M-1: prevents TOCTOU races on counter files.
func withCounterLock(path string, fn func(*memberCounter) error) error {
	lockPath := path + ".lock"
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("breakglass: mkdir: %w", err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("breakglass: open lock file: %w", err)
	}
	defer f.Close() //nolint:errcheck // defer close of lock file, error non-actionable on shutdown

	if err := flockAcquire(f); err != nil {
		return err
	}
	defer flockRelease(f)

	c, err := loadCounterLocked(path)
	if err != nil {
		return err
	}
	if err := fn(c); err != nil {
		return err
	}
	return saveCounterLocked(path, c)
}

// loadCounterLocked loads the counter file. Must be called with the lock held.
// N-5: corrupt counter file returns error instead of silently resetting.
func loadCounterLocked(path string) (*memberCounter, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &memberCounter{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("breakglass: read counter: %w", err)
	}
	var c memberCounter
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("breakglass: corrupt counter file %s: %w", path, err)
	}
	return &c, nil
}

// saveCounterLocked saves the counter file atomically. Must be called with the lock held.
func saveCounterLocked(path string, c *memberCounter) error {
	data, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("breakglass: marshal counter: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("breakglass: write counter: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("breakglass: rename counter: %w", err)
	}
	return nil
}

// CheckRateLimit returns ErrRateLimitExceeded if member has exceeded 3 opens in 24h.
// FIND2-016. M-1: uses withCounterLock for atomic read-check.
func CheckRateLimit(_ context.Context, member team.Member) error {
	path := memberCounterPath(member)
	var rateLimitErr error
	err := withCounterLock(path, func(c *memberCounter) error {
		now := time.Now()
		cutoff := now.Add(-24 * time.Hour)
		count := 0
		for _, t := range c.Opens {
			if t.After(cutoff) {
				count++
			}
		}
		if count >= 3 {
			rateLimitErr = ErrRateLimitExceeded
		}
		// No mutation — return nil so counter is saved unchanged.
		return nil
	})
	if err != nil {
		return err
	}
	return rateLimitErr
}

// CheckCoolingPeriod returns ErrCoolingPeriod if cooling period has not elapsed.
// FIND2-021: min 1h between close and next open. M-1: uses withCounterLock for atomic read-check.
func CheckCoolingPeriod(_ context.Context, member team.Member) error {
	path := memberCounterPath(member)
	var coolingErr error
	err := withCounterLock(path, func(c *memberCounter) error {
		if c.LastClose == nil {
			return nil
		}
		elapsed := time.Since(*c.LastClose)
		if elapsed < time.Hour {
			coolingErr = ErrCoolingPeriod
		}
		return nil
	})
	if err != nil {
		return err
	}
	return coolingErr
}

// Open opens a break-glass request.
// M-1: the rate-limit check, cooling-period check, and counter update are all
// performed atomically inside a single withCounterLock call.
func Open(ctx context.Context, member team.Member, reason string) (*BreakGlassRequest, error) {
	// S12-10: blocked during LLM sessions.
	if isLLMSession(ctx) {
		return nil, ErrLLMSessionBlocked
	}

	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("breakglass: generate id: %w", err)
	}

	now := time.Now().UTC()
	var req *BreakGlassRequest

	path := memberCounterPath(member)
	if err := withCounterLock(path, func(c *memberCounter) error {
		// FIND2-016: rate limit — prune stale opens first (M-2).
		cutoff := now.Add(-24 * time.Hour)
		pruned := c.Opens[:0]
		for _, t := range c.Opens {
			if t.After(cutoff) {
				pruned = append(pruned, t)
			}
		}
		c.Opens = pruned

		if len(c.Opens) >= 3 {
			return ErrRateLimitExceeded
		}

		// FIND2-021: cooling period check.
		if c.LastClose != nil {
			elapsed := now.Sub(*c.LastClose)
			if elapsed < time.Hour {
				return ErrCoolingPeriod
			}
		}

		// Record the open.
		c.Opens = append(c.Opens, now)

		req = &BreakGlassRequest{
			ID:         id,
			MemberHMAC: member.HMAC,
			Reason:     reason,
			Status:     BGOpen,
			OpenedAt:   now,
			AuditRef:   "breakglass/" + id,
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return req, nil
}

// Close closes an open break-glass session.
// M-1: the last-close timestamp update is performed atomically inside withCounterLock.
func Close(_ context.Context, req *BreakGlassRequest, member team.Member) error {
	if req.Status != BGOpen {
		return fmt.Errorf("breakglass: request %q is not open (status=%v)", req.ID, req.Status)
	}
	now := time.Now().UTC()
	req.Status = BGClosed
	req.ClosedAt = &now

	path := memberCounterPath(member)
	return withCounterLock(path, func(c *memberCounter) error {
		c.LastClose = &now
		return nil
	})
}

// generateID generates a random 16-byte hex ID.
func generateID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
