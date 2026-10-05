// Package approval manages pending gateway action approvals.
//
// Approval files are stored at approvalsDir/<token>.json with mode 0o600.
// Every decision (approve or deny) is signed with the approver key, an
// Ed25519 key derived from a passphrase only a human types into a terminal;
// Verify accepts an approval only when its signature checks out against the
// approver public key.
package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
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
	ErrUnsigned     = errors.New("approval: decision is not signed by the approver key")
	ErrHashRequired = errors.New("approval: request hash is required")
	ErrChanged      = errors.New("approval: request changed after it was shown; review it again")
	ErrTTLTooLong   = errors.New("approval: request asks for a validity longer than allowed")
	ErrUsed         = errors.New("approval: already used")
)

// MaxTTL bounds how long a request stays open. Requests are written by the
// requester, so a longer expiry on disk is refused rather than trusted.
const MaxTTL = time.Hour

// UseWindow is how long after the decision an approval can be used.
const UseWindow = 15 * time.Minute

// Status constants.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
)

// ApprovalRequest represents an approval record.
type ApprovalRequest struct {
	Token       string    `json:"token"` // "apv_" + 32 lowercase hex
	Actor       string    `json:"actor"`
	Capability  string    `json:"capability"`
	Connection  string    `json:"connection"`
	RequestHash string    `json:"request_hash"` // HMAC of original request
	Status      string    `json:"status"`       // "pending"|"approved"|"denied"|"expired"
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	Note        string    `json:"note,omitempty"`
	DecidedAt   time.Time `json:"decided_at,omitzero"`
	Signature   string    `json:"signature,omitempty"`
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
	ttl = min(ttl, MaxTTL)

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
	root, err := os.OpenRoot(approvalsDir)
	if err != nil {
		return nil, fmt.Errorf("approval: open %q: %w", approvalsDir, err)
	}
	defer func() { _ = root.Close() }()
	if err := writeApproval(root, ar); err != nil {
		return nil, err
	}
	return ar, nil
}

// Get returns the record for token, whatever its status.
func Get(_ context.Context, approvalsDir, token string) (*ApprovalRequest, error) {
	if !ValidToken(token) {
		return nil, ErrNotFound
	}
	root, err := openRoot(approvalsDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return readApproval(root, token)
}

// Pending returns all pending (non-expired) approvals from approvalsDir.
func Pending(ctx context.Context, approvalsDir string) ([]ApprovalRequest, error) {
	return pendingWithClock(ctx, approvalsDir, defaultClock)
}

func pendingWithClock(_ context.Context, approvalsDir string, clk Clock) ([]ApprovalRequest, error) {
	records, err := readAll(approvalsDir)
	if err != nil {
		return nil, err
	}
	now := clk.Now()
	var result []ApprovalRequest
	for _, ar := range records {
		if ar.Status == StatusPending && !ar.ExpiresAt.Before(now) {
			result = append(result, *ar)
		}
	}
	return result, nil
}

// List returns all approval requests with StatusPending from approvalsDir,
// including those that are past their TTL but have not yet been swept.
// Past-TTL entries are reported with StatusExpired. Results are sorted by
// CreatedAt ascending.
func List(_ context.Context, approvalsDir string) ([]*ApprovalRequest, error) {
	return listWithClock(approvalsDir, defaultClock)
}

func listWithClock(approvalsDir string, clk Clock) ([]*ApprovalRequest, error) {
	records, err := readAll(approvalsDir)
	if err != nil {
		return nil, err
	}
	var result []*ApprovalRequest
	for _, ar := range records {
		if ar.Status == StatusPending {
			result = append(result, ar)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
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
// StatusExpired. Decided entries are left alone and unreadable entries are
// skipped.
func ExpireOldPending(_ context.Context, approvalsDir string) (int, error) {
	return expireOldPendingWithClock(approvalsDir, defaultClock)
}

func expireOldPendingWithClock(approvalsDir string, clk Clock) (int, error) {
	root, err := openRoot(approvalsDir)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = root.Close() }()
	tokens, err := listTokens(root)
	if err != nil {
		return 0, err
	}

	now := clk.Now()
	var expired int
	for _, tok := range tokens {
		ar, err := readApproval(root, tok)
		if err != nil || ar.Status != StatusPending || !ar.ExpiresAt.Before(now) {
			continue
		}
		ar.Status = StatusExpired
		ar.Note = "auto-denied by TTL sweep"
		if err := writeApproval(root, ar); err != nil {
			continue
		}
		expired++
	}
	return expired, nil
}

// Digest identifies the exact content of a record. A decision names the
// digest of the record the human was shown, and is refused if the file no
// longer matches it.
func Digest(ar *ApprovalRequest) string {
	b, _ := json.Marshal(ar)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Approve marks the approval approved and signs the decision with key.
// shown is the Digest of the record the approver reviewed.
func Approve(ctx context.Context, approvalsDir, token, shown string, key ed25519.PrivateKey) error {
	return ApproveWithReason(ctx, approvalsDir, token, shown, "", key)
}

// ApproveWithReason is Approve with a reason note.
func ApproveWithReason(_ context.Context, approvalsDir, token, shown, reason string, key ed25519.PrivateKey) error {
	return decide(approvalsDir, token, shown, StatusApproved, reason, key, defaultClock)
}

// Deny marks the approval denied and signs the decision with key. shown is
// the Digest of the record the approver reviewed.
func Deny(ctx context.Context, approvalsDir, token, shown string, key ed25519.PrivateKey) error {
	return DenyWithReason(ctx, approvalsDir, token, shown, "", key)
}

// DenyWithReason is Deny with a reason note.
func DenyWithReason(_ context.Context, approvalsDir, token, shown, reason string, key ed25519.PrivateKey) error {
	return decide(approvalsDir, token, shown, StatusDenied, reason, key, defaultClock)
}

// Verify checks that token exists, is approved by a decision signed with
// the approver key pub, is bound to reqHash, has not expired and was
// decided within UseWindow, and then consumes it: an approval allows exactly
// one use.
func Verify(ctx context.Context, approvalsDir, token, reqHash string, pub ed25519.PublicKey) error {
	return verifyWithClock(ctx, approvalsDir, token, reqHash, pub, defaultClock)
}

func verifyWithClock(_ context.Context, approvalsDir, token, reqHash string, pub ed25519.PublicKey, clk Clock) error {
	if reqHash == "" {
		return ErrHashRequired
	}
	if !ValidToken(token) {
		return ErrNotFound
	}
	root, err := openRoot(approvalsDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	ar, err := readApproval(root, token)
	if err != nil {
		return ErrNotFound
	}
	if !signatureValid(ar, pub) {
		return ErrUnsigned
	}
	if ar.ExpiresAt.Before(clk.Now()) {
		return ErrExpired
	}
	if ar.Status != StatusApproved {
		return fmt.Errorf("approval: status is %q, not approved", ar.Status)
	}
	if ar.RequestHash != reqHash {
		return errors.New("approval: request hash mismatch")
	}
	now := clk.Now()
	if ar.DecidedAt.After(now) || now.Sub(ar.DecidedAt) > UseWindow {
		return ErrExpired
	}
	return consume(root, token)
}

// consume records the single use of an approval. The marker is created
// exclusively, so concurrent verifiers cannot both succeed.
func consume(root *os.Root, token string) error {
	f, err := root.OpenFile(token+".used", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return ErrUsed
	}
	if err != nil {
		return fmt.Errorf("approval: record use: %w", err)
	}
	return f.Close()
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

func decide(approvalsDir, token, shown, status, reason string, key ed25519.PrivateKey, clk Clock) error {
	if len(key) != ed25519.PrivateKeySize {
		return ErrUnsigned
	}
	if !ValidToken(token) {
		return ErrNotFound
	}
	root, err := openRoot(approvalsDir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	ar, err := readApproval(root, token)
	if err != nil {
		return err
	}
	if Digest(ar) != shown {
		return ErrChanged
	}
	if ar.Status == StatusApproved || ar.Status == StatusDenied {
		return ErrAlreadyActed
	}
	if ar.Status == StatusExpired || ar.ExpiresAt.Before(clk.Now()) {
		return &ErrExpiredTTL{ExpiresAt: ar.ExpiresAt}
	}
	if ar.ExpiresAt.Sub(ar.CreatedAt) > MaxTTL {
		return ErrTTLTooLong
	}
	ar.Status = status
	if reason != "" {
		ar.Note = reason
	}
	ar.DecidedAt = clk.Now().UTC()
	ar.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, decisionMessage(ar)))
	return writeApproval(root, ar)
}

const decisionDomain = "keylatch/approval-decision/v1\n"

// decisionMessage is the byte string an approver signs: every field that
// identifies the request and the decision, so a signature cannot be moved
// to another request or replayed with a different status.
func decisionMessage(ar *ApprovalRequest) []byte {
	b, _ := json.Marshal(struct {
		Token       string `json:"token"`
		Actor       string `json:"actor"`
		Capability  string `json:"capability"`
		Connection  string `json:"connection"`
		RequestHash string `json:"request_hash"`
		Status      string `json:"status"`
		Note        string `json:"note"`
		CreatedAt   string `json:"created_at"`
		ExpiresAt   string `json:"expires_at"`
		DecidedAt   string `json:"decided_at"`
	}{
		Token:       ar.Token,
		Actor:       ar.Actor,
		Capability:  ar.Capability,
		Connection:  ar.Connection,
		RequestHash: ar.RequestHash,
		Status:      ar.Status,
		Note:        ar.Note,
		CreatedAt:   ar.CreatedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:   ar.ExpiresAt.UTC().Format(time.RFC3339Nano),
		DecidedAt:   ar.DecidedAt.UTC().Format(time.RFC3339Nano),
	})
	return append([]byte(decisionDomain), b...)
}

func signatureValid(ar *ApprovalRequest, pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize || ar.Signature == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(ar.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, decisionMessage(ar), sig)
}

func newApprovalToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "apv_" + hex.EncodeToString(b), nil
}

// tokenPattern matches exactly what newApprovalToken generates. Tokens come
// from the command line, so anything else is refused before it can name a
// file.
var tokenPattern = regexp.MustCompile(`^apv_[0-9a-f]{32}$`)

// ValidToken reports whether token has the approval token format.
func ValidToken(token string) bool {
	return tokenPattern.MatchString(token)
}

// openRoot confines every file access to approvalsDir: os.Root refuses
// paths and symlinks that resolve outside it.
func openRoot(approvalsDir string) (*os.Root, error) {
	root, err := os.OpenRoot(approvalsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("approval: open %q: %w", approvalsDir, err)
	}
	return root, nil
}

func listTokens(root *os.Root) ([]string, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("approval: open approvals directory: %w", err)
	}
	defer func() { _ = dir.Close() }()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("approval: readdir: %w", err)
	}
	var tokens []string
	for _, name := range names {
		if tok, ok := strings.CutSuffix(name, ".json"); ok && ValidToken(tok) {
			tokens = append(tokens, tok)
		}
	}
	sort.Strings(tokens)
	return tokens, nil
}

func readAll(approvalsDir string) ([]*ApprovalRequest, error) {
	root, err := openRoot(approvalsDir)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	tokens, err := listTokens(root)
	if err != nil {
		return nil, err
	}
	var records []*ApprovalRequest
	for _, tok := range tokens {
		if ar, err := readApproval(root, tok); err == nil {
			records = append(records, ar)
		}
	}
	return records, nil
}

// readApproval reads <token>.json from root. Only regular files whose
// recorded token matches their name are accepted.
func readApproval(root *os.Root, token string) (*ApprovalRequest, error) {
	name := token + ".json"
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("approval: stat %q: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("approval: %q is not a regular file", name)
	}
	data, err := root.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("approval: read %q: %w", name, err)
	}
	var ar ApprovalRequest
	if err := json.Unmarshal(data, &ar); err != nil {
		return nil, fmt.Errorf("approval: parse %q: %w", name, err)
	}
	if ar.Token != token {
		return nil, fmt.Errorf("approval: %q records a different token", name)
	}
	return &ar, nil
}

func writeApproval(root *os.Root, ar *ApprovalRequest) error {
	if !ValidToken(ar.Token) {
		return ErrNotFound
	}
	data, err := json.MarshalIndent(ar, "", "  ")
	if err != nil {
		return fmt.Errorf("approval: marshal: %w", err)
	}
	name := ar.Token + ".json"
	tmp := name + ".tmp"
	if err := root.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("approval: write tmp: %w", err)
	}
	if err := root.Rename(tmp, name); err != nil {
		_ = root.Remove(tmp)
		return fmt.Errorf("approval: rename: %w", err)
	}
	return nil
}
