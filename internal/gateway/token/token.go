// Package token implements JWT-shaped scoped gateway tokens.
//
// Security invariants:
//   - LLMSession is derived from the JWT claim, NEVER from os.Getenv.
//   - Callers MUST set spec.LLMSession from llmcontext.IsLLMSession() in their own process.
//   - MaxUses enforcement uses flock + append-only consumption log.
//   - No credential bytes appear in any error message or log.
package token

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors.
var (
	ErrTokenExpired       = errors.New("token: expired")
	ErrTokenRevoked       = errors.New("token: revoked")
	ErrTokenExhausted     = errors.New("token: max uses reached")
	ErrFDNonceMismatch    = errors.New("token: fd nonce mismatch")
	ErrTokenNotFound      = errors.New("token: not found")
	ErrInvalidRuntime     = errors.New("token: direct_classic_sandboxed is not a gateway runtime")
	ErrTokenPersistFailed = errors.New("token: persist failed")
	ErrMaxUsesRequired    = errors.New("token: MaxUses required for runner-minted tokens")
)

var (
	hookMu     sync.Mutex
	MintHook   func()
	RevokeHook func()
)

// SetMintHook atomically replaces MintHook; safe for concurrent use in tests.
func SetMintHook(fn func()) {
	hookMu.Lock()
	MintHook = fn
	hookMu.Unlock()
}

// SetRevokeHook atomically replaces RevokeHook; safe for concurrent use in tests.
func SetRevokeHook(fn func()) {
	hookMu.Lock()
	RevokeHook = fn
	hookMu.Unlock()
}

// Token is the persisted gateway token record.
type Token struct {
	ID                 string     `json:"id"`
	Accessor           string     `json:"accessor"`
	Actor              string     `json:"actor"`
	Capabilities       []string   `json:"capabilities"`
	CommandHash        string     `json:"command_hash,omitempty"`
	CWDHash            string     `json:"cwd_hash,omitempty"`
	IssuedAt           time.Time  `json:"issued_at"`
	ExpiresAt          time.Time  `json:"expires_at"`
	MaxUses            int        `json:"max_uses,omitempty"`
	UsesRemaining      int        `json:"uses_remaining,omitempty"` // legacy compat
	ConsumptionLogPath string     `json:"consumption_log_path,omitempty"`
	Revoked            bool       `json:"revoked"`
	RevokedAt          *time.Time `json:"revoked_at,omitempty"`
	Parent             string     `json:"parent,omitempty"`
	LLMSession         bool       `json:"llm_session"`
	FDNonceHash        string     `json:"fd_nonce_hash,omitempty"` // ephemeral nonce hash

	// Approval root claims.
	// All root IDs are HMAC'd; never raw.
	// ApprovalRootHMAC is the HMAC of the primary approval root spec ID.
	ApprovalRootHMAC string `json:"approval_root_hmac,omitempty"`
	// ApprovalCapability is the capability that was approved (e.g. "inject").
	ApprovalCapability string `json:"approval_capability,omitempty"`
	// ApprovalMaxAgeSec is the maximum age (seconds) of a presence proof accepted for this token.
	ApprovalMaxAgeSec int `json:"approval_max_age_sec,omitempty"`
	// ApprovalExpiry is when the hardware approval expires (may be before TokenExpiry).
	ApprovalExpiry *time.Time `json:"approval_expiry,omitempty"`
	// ApprovalBinding is the binding mode for the approval challenge ("none", "command", "cwd", "full").
	ApprovalBinding string `json:"approval_binding,omitempty"`
	// TwoPerson indicates this token required two distinct hardware approvals.
	TwoPerson bool `json:"two_person,omitempty"`
	// ApprovalRootHMACs holds all HMAC'd root IDs that contributed approvals (two-person use).
	ApprovalRootHMACs []string `json:"approval_root_hmacs,omitempty"`
}

// TokenSpec carries parameters for Mint.
type TokenSpec struct {
	Actor        string
	Capabilities []string
	Command      string
	CWD          string
	TTL          time.Duration
	MaxUses      int // 0 = unlimited (explicit); default for runner-minted = 1
	Parent       string
	LLMSession   bool
	FDNonce      []byte // 32-byte ephemeral nonce from pipe
	StorePath    string // defaults to paths.GatewayTokens(env)
	SigningKey   []byte // 32-byte; loaded from ~/.keylatch/gateway/signing.key

	// Approval root parameters.
	// ApprovalRootID is the raw root spec ID; it will be HMAC'd before embedding in JWT/Token.
	ApprovalRootID string
	// ApprovalCapability is the capability being approved.
	ApprovalCapability string
	// ApprovalMaxAgeSec is the maximum accepted presence proof age for this token.
	ApprovalMaxAgeSec int
	// ApprovalExpiry is the hardware approval expiry (independent of JWT exp).
	ApprovalExpiry *time.Time
	// ApprovalBinding is the challenge binding mode.
	ApprovalBinding string
	// TwoPerson requires two distinct root approvals.
	TwoPerson bool
	// ApprovalRootIDs are raw root spec IDs for two-person approvals; each HMAC'd.
	ApprovalRootIDs []string
}

// ListOpts controls which tokens are returned by List.
type ListOpts struct {
	IncludeExpired bool
	IncludeRevoked bool
}

// gatewayClaims are the JWT claims for keylatch gateway tokens.
type gatewayClaims struct {
	jwt.RegisteredClaims
	Actor       string   `json:"actor"`
	Caps        []string `json:"caps"`
	CommandHash string   `json:"cmd_hash,omitempty"`
	CWDHash     string   `json:"cwd_hash,omitempty"`
	LLMSession  bool     `json:"llm_session"`

	// Approval root claims (root IDs are HMAC'd, never raw).
	ApprovalRootHMAC  string   `json:"apv_root_hmac,omitempty"`
	ApprovalCap       string   `json:"apv_cap,omitempty"`
	ApprovalMaxAgeSec int      `json:"apv_max_age_sec,omitempty"`
	ApprovalExpiry    string   `json:"apv_exp,omitempty"` // RFC3339; separate from JWT exp
	ApprovalBinding   string   `json:"apv_binding,omitempty"`
	TwoPerson         bool     `json:"apv_two_person,omitempty"`
	ApprovalRootHMACs []string `json:"apv_root_hmacs,omitempty"`
}

// Mint produces a HS256 JWT AND persists the Token record.
//
// JWT claims: jti, iat, exp, actor, caps ([]string), cmd_hash, cwd_hash, llm_session.
// If spec.FDNonce is non-empty, Token.FDNonceHash = HMAC-SHA256(signingKey, fdNonce) hex-encoded.
// If spec.MaxUses > 0, Token.ConsumptionLogPath is set.
// Callers MUST set spec.LLMSession from llmcontext.IsLLMSession() in their own process.
func Mint(spec TokenSpec) (string, *Token, error) {
	if len(spec.SigningKey) != 32 {
		return "", nil, fmt.Errorf("token: signing key must be 32 bytes")
	}

	if spec.MaxUses > 0 && spec.StorePath == "" {
		return "", nil, fmt.Errorf("token: MaxUses > 0 requires StorePath to be set for cross-process safety")
	}

	// Generate token ID (UUID v4).
	id, err := newUUID()
	if err != nil {
		return "", nil, fmt.Errorf("token: generate id: %w", err)
	}

	// Compute accessor = HMAC-SHA256(signingKey, id).
	accessor := hmacHex(spec.SigningKey, []byte(id))

	now := time.Now().UTC()
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	expiresAt := now.Add(ttl)

	// Compute command and CWD hashes.
	var cmdHash, cwdHash string
	if spec.Command != "" {
		cmdHash = hmacHex(spec.SigningKey, []byte(spec.Command))
	}
	if spec.CWD != "" {
		cwdHash = hmacHex(spec.SigningKey, []byte(spec.CWD))
	}

	// Compute HMAC'd approval root IDs (never embed raw root IDs).
	var approvalRootHMAC string
	var approvalRootHMACs []string
	var approvalExpiryStr string
	if spec.ApprovalRootID != "" {
		approvalRootHMAC = hmacHex(spec.SigningKey, []byte(spec.ApprovalRootID))
	}
	for _, rid := range spec.ApprovalRootIDs {
		approvalRootHMACs = append(approvalRootHMACs, hmacHex(spec.SigningKey, []byte(rid)))
	}
	if spec.ApprovalExpiry != nil {
		approvalExpiryStr = spec.ApprovalExpiry.UTC().Format(time.RFC3339)
	}

	// Build JWT claims.
	claims := gatewayClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        id,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		Actor:             spec.Actor,
		Caps:              spec.Capabilities,
		CommandHash:       cmdHash,
		CWDHash:           cwdHash,
		LLMSession:        spec.LLMSession,
		ApprovalRootHMAC:  approvalRootHMAC,
		ApprovalCap:       spec.ApprovalCapability,
		ApprovalMaxAgeSec: spec.ApprovalMaxAgeSec,
		ApprovalExpiry:    approvalExpiryStr,
		ApprovalBinding:   spec.ApprovalBinding,
		TwoPerson:         spec.TwoPerson,
		ApprovalRootHMACs: approvalRootHMACs,
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := jwtToken.SignedString(spec.SigningKey)
	if err != nil {
		return "", nil, fmt.Errorf("token: sign: %w", err)
	}

	t := &Token{
		ID:            id,
		Accessor:      accessor,
		Actor:         spec.Actor,
		Capabilities:  spec.Capabilities,
		CommandHash:   cmdHash,
		CWDHash:       cwdHash,
		IssuedAt:      now,
		ExpiresAt:     expiresAt,
		MaxUses:       spec.MaxUses,
		UsesRemaining: spec.MaxUses,
		Parent:        spec.Parent,
		LLMSession:    spec.LLMSession,

		// Approval root fields (HMAC'd).
		ApprovalRootHMAC:   approvalRootHMAC,
		ApprovalCapability: spec.ApprovalCapability,
		ApprovalMaxAgeSec:  spec.ApprovalMaxAgeSec,
		ApprovalExpiry:     spec.ApprovalExpiry,
		ApprovalBinding:    spec.ApprovalBinding,
		TwoPerson:          spec.TwoPerson,
		ApprovalRootHMACs:  approvalRootHMACs,
	}

	// FD nonce hash.
	if len(spec.FDNonce) > 0 {
		t.FDNonceHash = hmacHex(spec.SigningKey, spec.FDNonce)
	}

	// Consumption log path for MaxUses tokens.
	if spec.MaxUses > 0 && spec.StorePath != "" {
		dir := filepath.Join(filepath.Dir(spec.StorePath), "gateway-consumption")
		t.ConsumptionLogPath = filepath.Join(dir, id+".consumption.log")
	}

	// Persist token record.
	if spec.StorePath != "" {
		if err := persistToken(spec.StorePath, *t); err != nil {
			return "", nil, ErrTokenPersistFailed
		}
	}
	hookMu.Lock()
	h := MintHook
	hookMu.Unlock()
	if h != nil {
		h()
	}

	return signed, t, nil
}

// Verify parses the JWT, verifies signature + exp + not-revoked + not-exhausted.
//
// If r is non-nil and Token.FDNonceHash is set: reads X-Keylatch-FD-Nonce header,
// computes HMAC(signingKey, headerBytes), constant-time compares to FDNonceHash.
// Mismatch → ErrFDNonceMismatch.
// For MaxUses>0 tokens, atomically appends one consumption record
// to ConsumptionLogPath under flock.
func Verify(jwtStr string, r *http.Request, signingKey []byte, storePath string) (*Token, error) {
	if len(signingKey) != 32 {
		return nil, fmt.Errorf("token: signing key must be 32 bytes")
	}

	// Parse and verify JWT signature + expiry.
	claims := &gatewayClaims{}
	parsed, err := jwt.ParseWithClaims(jwtStr, claims, func(_ *jwt.Token) (interface{}, error) {
		return signingKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("token: invalid: %w", err)
	}
	if !parsed.Valid {
		return nil, fmt.Errorf("token: not valid")
	}

	tokenID := claims.ID

	// Load persisted token record.
	t, err := loadToken(storePath, tokenID)
	if err != nil {
		return nil, ErrTokenNotFound
	}

	// Check revocation.
	if t.Revoked {
		return nil, ErrTokenRevoked
	}

	// Check expiry (belt-and-suspenders beyond JWT exp).
	if time.Now().UTC().After(t.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// FD nonce verification.
	if t.FDNonceHash != "" && r != nil {
		nonceHeader := r.Header.Get("X-Keylatch-FD-Nonce")
		if nonceHeader == "" {
			return nil, ErrFDNonceMismatch
		}
		nonceBytes, decErr := base64.StdEncoding.DecodeString(nonceHeader)
		if decErr != nil {
			return nil, ErrFDNonceMismatch
		}
		expected := hmacHex(signingKey, nonceBytes)
		if !hmac.Equal([]byte(expected), []byte(t.FDNonceHash)) {
			return nil, ErrFDNonceMismatch
		}
	}

	// MaxUses enforcement.
	if t.MaxUses > 0 {
		if !consumeUseForToken(t) {
			return nil, ErrTokenExhausted
		}
	}

	return t, nil
}

// Revoke marks the token and its children as revoked.
func Revoke(id string, storePath string) error {
	storeMu.Lock()
	defer storeMu.Unlock()

	if err := withStoreLock(storePath, func() error {
		tokens, err := readTokens(storePath)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		found := false
		for i := range tokens {
			if tokens[i].ID == id {
				tokens[i].Revoked = true
				tokens[i].RevokedAt = &now
				found = true
			}
		}
		if !found {
			return ErrTokenNotFound
		}
		// Cascade to children.
		for i := range tokens {
			if tokens[i].Parent == id && !tokens[i].Revoked {
				tokens[i].Revoked = true
				tokens[i].RevokedAt = &now
			}
		}
		return writeTokens(storePath, tokens)
	}); err != nil {
		return err
	}
	hookMu.Lock()
	rh := RevokeHook
	hookMu.Unlock()
	if rh != nil {
		rh()
	}
	return nil
}

// List returns tokens from storePath filtered by opts.
func List(opts ListOpts, storePath string) ([]Token, error) {
	tokens, err := readTokens(storePath)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var result []Token
	for _, t := range tokens {
		if !opts.IncludeRevoked && t.Revoked {
			continue
		}
		if !opts.IncludeExpired && t.ExpiresAt.Before(now) {
			continue
		}
		result = append(result, t)
	}
	return result, nil
}

// --- storage helpers ---

func readTokens(storePath string) ([]Token, error) {
	if storePath == "" {
		return nil, nil
	}
	data, err := os.ReadFile(storePath)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("token: read %q: %w", storePath, err)
	}
	var tokens []Token
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, fmt.Errorf("token: parse %q: %w", storePath, err)
	}
	return tokens, nil
}

func writeTokens(storePath string, tokens []Token) error {
	if err := os.MkdirAll(filepath.Dir(storePath), 0o700); err != nil {
		return fmt.Errorf("token: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return fmt.Errorf("token: marshal: %w", err)
	}
	tmp := storePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("token: write tmp: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, storePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("token: rename: %w", err)
	}
	return nil
}

// persistToken appends a new token to the store.
// Thread-safe via storeMu (same-process goroutines) and withStoreLock (cross-process).
var storeMu sync.Mutex

func persistToken(storePath string, t Token) error {
	storeMu.Lock()
	defer storeMu.Unlock()

	return withStoreLock(storePath, func() error {
		tokens, err := readTokens(storePath)
		if err != nil {
			return err
		}
		tokens = append(tokens, t)
		return writeTokens(storePath, tokens)
	})
}

// loadToken finds a token by ID in the store.
func loadToken(storePath string, id string) (*Token, error) {
	if storePath == "" {
		return nil, ErrTokenNotFound
	}
	tokens, err := readTokens(storePath)
	if err != nil {
		return nil, err
	}
	for i := range tokens {
		if tokens[i].ID == id {
			return &tokens[i], nil
		}
	}
	return nil, ErrTokenNotFound
}

// --- HMAC helpers ---

func hmacHex(key, data []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// --- UUID ---

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// --- consumption log (flock-based, delegates to platform-specific impl) ---

func consumeUseForToken(t *Token) bool {
	if t.ConsumptionLogPath == "" {
		// In-memory fallback: not safe across processes.
		slog.Warn("token use counting: no ConsumptionLogPath set; using in-memory counter (not safe across processes)", "token_id", t.ID)
		if t.UsesRemaining <= 0 {
			return false
		}
		t.UsesRemaining--
		return true
	}
	return consumeTokenUseLog(t)
}

// isReadClassCap mirrors the grant/policy read-class check.
func isReadClassCap(cap string) bool {
	switch cap {
	case "read", "export":
		return true
	}
	return strings.HasSuffix(cap, ".reveal") || strings.HasSuffix(cap, ".dump")
}

// IsReadClassCap is exported for use by the gateway handler (LLM session gate).
func IsReadClassCap(cap string) bool {
	return isReadClassCap(cap)
}

// HasCapability checks whether token t has the given capability.
// Supports wildcard matching: "provider.*" matches "provider.<anything>".
func HasCapability(t *Token, cap string) bool {
	for _, c := range t.Capabilities {
		if c == cap {
			return true
		}
		// Wildcard: "provider.*" matches "provider.<anything>"
		if strings.HasSuffix(c, ".*") {
			prefix := strings.TrimSuffix(c, "*") // "provider."
			if strings.HasPrefix(cap, prefix) {
				return true
			}
		}
	}
	return false
}

// consumeTokenLog is the internal flock-based consumption struct.
type consumeTokenLogEntry struct {
	TokenID string `json:"token_id"`
	UsedAt  string `json:"used_at"`
}

// countTokenLogLines counts non-empty lines in a consumption log file.
func countTokenLogLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close() //nolint:errcheck // defer close in read-only path, error non-actionable
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		if sc.Text() != "" {
			n++
		}
	}
	return n, sc.Err()
}
