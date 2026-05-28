// Package approval manages pending gateway action approvals.
//
// Approval files are stored at approvalsDir/<token>.json with mode 0o600.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Clock is an interface that wraps time.Now for testability.
// Production code uses RealClock; tests inject a fake.
type Clock interface {
	Now() time.Time
}

// RealClock is the production Clock implementation.
type RealClock struct{}

// Now returns the current UTC time.
func (RealClock) Now() time.Time { return time.Now().UTC() }

// defaultClock is used by package-level functions that do not accept a Clock.
var defaultClock Clock = RealClock{}

// Sentinel errors.
var (
	ErrNotFound     = errors.New("approval: not found")
	ErrExpired      = errors.New("approval: expired")
	ErrAlreadyActed = errors.New("approval: already approved or denied")
)

// Status constants.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
)

// ApprovalRequest represents a pending approval record.
type ApprovalRequest struct {
	Token       string    `json:"token"` // "apv_<random16hex>"
	Actor       string    `json:"actor"`
	Capability  string    `json:"capability"`
	Connection  string    `json:"connection"`
	RequestHash string    `json:"request_hash"` // HMAC of original request
	Status      string    `json:"status"`       // "pending"|"approved"|"denied"|"expired"
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	Note        string    `json:"note,omitempty"`
}

// RequestNew creates a pending approval at approvalsDir/<token>.json (mode 0o600).
func RequestNew(_ context.Context, approvalsDir, actor, capability, connection string, reqHash string, ttl time.Duration) (*ApprovalRequest, error) {
	tok, err := newApprovalToken()
	if err != nil {
		return nil, fmt.Errorf("approval: generate token: %w", err)
	}

	now := time.Now().UTC()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	ar := &ApprovalRequest{
		Token:       tok,
		Actor:       actor,
		Capability:  capability,
		Connection:  connection,
		RequestHash: reqHash,
		Status:      StatusPending,
		ExpiresAt:   now.Add(ttl),
		CreatedAt:   now,
	}

	if err := os.MkdirAll(approvalsDir, 0o700); err != nil {
		return nil, fmt.Errorf("approval: mkdir %q: %w", approvalsDir, err)
	}

	path := filepath.Join(approvalsDir, tok+".json")
	if err := writeApproval(path, ar); err != nil {
		return nil, err
	}

	return ar, nil
}

// Pending returns all pending (non-expired) approvals from approvalsDir.
func Pending(ctx context.Context, approvalsDir string) ([]ApprovalRequest, error) {
	return pendingWithClock(ctx, approvalsDir, defaultClock)
}

// pendingWithClock is the internal implementation with an injected clock.
func pendingWithClock(_ context.Context, approvalsDir string, clk Clock) ([]ApprovalRequest, error) {
	entries, err := os.ReadDir(approvalsDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("approval: readdir %q: %w", approvalsDir, err)
	}

	now := clk.Now()
	var result []ApprovalRequest
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		ar, err := readApproval(filepath.Join(approvalsDir, entry.Name()))
		if err != nil {
			continue
		}
		if ar.Status != StatusPending {
			continue
		}
		if ar.ExpiresAt.Before(now) {
			continue
		}
		result = append(result, *ar)
	}
	return result, nil
}

// List returns all approval requests with StatusPending from approvalsDir,
// including those that are past their TTL but have not yet been swept.
// Callers should display the effective status using EffectiveStatus.
// Results are sorted by CreatedAt ascending.
func List(_ context.Context, approvalsDir string) ([]*ApprovalRequest, error) {
	return listWithClock(approvalsDir, defaultClock)
}

// listWithClock is the internal implementation with an injected clock.
func listWithClock(approvalsDir string, clk Clock) ([]*ApprovalRequest, error) {
	entries, err := os.ReadDir(approvalsDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("approval: readdir %q: %w", approvalsDir, err)
	}

	var result []*ApprovalRequest
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		ar, err := readApproval(filepath.Join(approvalsDir, entry.Name()))
		if err != nil {
			continue
		}
		if ar.Status != StatusPending {
			continue
		}
		result = append(result, ar)
	}

	// Stable sort by CreatedAt ascending.
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})

	// Annotate past-TTL entries so callers can display "expired".
	now := clk.Now()
	for _, ar := range result {
		if ar.ExpiresAt.Before(now) {
			ar.Status = StatusExpired
		}
	}
	return result, nil
}

// EffectiveStatus returns the display status for an approval request,
// accounting for TTL expiry without requiring a background sweep.
func EffectiveStatus(ar *ApprovalRequest, clk Clock) string {
	if ar.Status == StatusPending && ar.ExpiresAt.Before(clk.Now()) {
		return StatusExpired
	}
	return ar.Status
}

// ExpireOldPending transitions any pending approval past its ExpiresAt to
// StatusExpired and writes the updated file. It skips entries that are already
// decided (approved/denied/expired). Races are tolerated: if a file disappears
// between ReadDir and read, it is skipped silently.
//
// This is the background sweep function. In production it is called by the
// gateway on a timer. In tests it is called directly.
func ExpireOldPending(_ context.Context, approvalsDir string) (int, error) {
	return expireOldPendingWithClock(approvalsDir, defaultClock)
}

// expireOldPendingWithClock is the internal implementation with an injected clock.
func expireOldPendingWithClock(approvalsDir string, clk Clock) (int, error) {
	entries, err := os.ReadDir(approvalsDir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("approval: readdir %q: %w", approvalsDir, err)
	}

	now := clk.Now()
	var expired int
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(approvalsDir, entry.Name())
		ar, err := readApproval(path)
		if err != nil {
			continue // skip corrupt / missing files silently
		}
		if ar.Status != StatusPending {
			continue // already decided — do not double-decide
		}
		if !ar.ExpiresAt.Before(now) {
			continue // still within TTL
		}
		ar.Status = StatusExpired
		ar.Note = "auto-denied by TTL sweep"
		if err := writeApproval(path, ar); err != nil {
			continue // tolerate write errors — sweep is best-effort
		}
		expired++
	}
	return expired, nil
}

// Approve marks the approval approved.
func Approve(_ context.Context, approvalsDir, token string) error {
	return updateStatus(approvalsDir, token, StatusApproved, "")
}

// ApproveWithReason marks the approval approved with an optional reason note.
func ApproveWithReason(_ context.Context, approvalsDir, token, reason string) error {
	return updateStatus(approvalsDir, token, StatusApproved, reason)
}

// Deny marks the approval denied.
func Deny(_ context.Context, approvalsDir, token string) error {
	return updateStatus(approvalsDir, token, StatusDenied, "")
}

// DenyWithReason marks the approval denied with an optional reason note.
func DenyWithReason(_ context.Context, approvalsDir, token, reason string) error {
	return updateStatus(approvalsDir, token, StatusDenied, reason)
}

// Verify checks that token exists, is approved, not expired, and request hash matches.
func Verify(ctx context.Context, approvalsDir, token, reqHash string) error {
	return verifyWithClock(ctx, approvalsDir, token, reqHash, defaultClock)
}

// verifyWithClock is the internal implementation with an injected clock.
func verifyWithClock(_ context.Context, approvalsDir, token, reqHash string, clk Clock) error {
	path := filepath.Join(approvalsDir, token+".json")
	ar, err := readApproval(path)
	if err != nil {
		return ErrNotFound
	}
	if ar.ExpiresAt.Before(clk.Now()) {
		return ErrExpired
	}
	if ar.Status != StatusApproved {
		return fmt.Errorf("approval: status is %q, not approved", ar.Status)
	}
	if reqHash != "" && ar.RequestHash != reqHash {
		return fmt.Errorf("approval: request hash mismatch")
	}
	return nil
}

// --- helpers ---

func newApprovalToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "apv_" + hex.EncodeToString(b), nil
}

func readApproval(path string) (*ApprovalRequest, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("approval: read %q: %w", path, err)
	}
	var ar ApprovalRequest
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, fmt.Errorf("approval: parse %q: %w", path, err)
	}
	return &ar, nil
}

func writeApproval(path string, ar *ApprovalRequest) error {
	data, err := json.MarshalIndent(ar, "", "  ")
	if err != nil {
		return fmt.Errorf("approval: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("approval: write tmp: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("approval: rename: %w", err)
	}
	return nil
}

// ErrExpiredTTL is returned when the caller tries to approve/deny an expired approval.
// It wraps ErrAlreadyActed semantically but carries the expiry timestamp for display.
type ErrExpiredTTL struct {
	ExpiresAt time.Time
}

func (e *ErrExpiredTTL) Error() string {
	return fmt.Sprintf("approval: expired at %s and was auto-denied", e.ExpiresAt.UTC().Format(time.RFC3339))
}

func (e *ErrExpiredTTL) Is(target error) bool {
	return target == ErrExpired || target == ErrAlreadyActed
}

func updateStatus(approvalsDir, token, status, reason string) error {
	return updateStatusWithClock(approvalsDir, token, status, reason, defaultClock)
}

// updateStatusWithClock is the internal implementation with an injected clock.
func updateStatusWithClock(approvalsDir, token, status, reason string, clk Clock) error {
	path := filepath.Join(approvalsDir, token+".json")
	ar, err := readApproval(path)
	if err != nil {
		return err
	}
	if ar.Status == StatusApproved || ar.Status == StatusDenied {
		return ErrAlreadyActed
	}
	// Check TTL — a pending entry past ExpiresAt is effectively expired.
	if ar.Status == StatusPending && ar.ExpiresAt.Before(clk.Now()) {
		return &ErrExpiredTTL{ExpiresAt: ar.ExpiresAt}
	}
	if ar.Status == StatusExpired {
		return &ErrExpiredTTL{ExpiresAt: ar.ExpiresAt}
	}
	ar.Status = status
	if reason != "" {
		ar.Note = reason
	}
	return writeApproval(path, ar)
}
