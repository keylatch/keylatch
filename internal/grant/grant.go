// Package grant provides the capability grant surface for keylatch.
//
// Security invariants:
// - expired grants (ExpiresAt before now) MUST NOT match.
// - revoked grants MUST NOT match.
// - grants issued from an LLM session MUST NOT be returned by Find
// for read-class capabilities (read, export, *.reveal, *.dump).
// - MaxUses enforcement uses flock + append-only consumption log.
package grant

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// Grant records a capability grant issued by the CLI to a downstream process.
type Grant struct {
	ID                   string     `json:"id"`       // UUID v4
	Accessor             string     `json:"accessor"` // opaque HMAC handle
	Actor                string     `json:"actor"`
	Connection           string     `json:"connection"`
	Capability           string     `json:"capability"`
	Command              string     `json:"command,omitempty"`
	CWD                  string     `json:"cwd,omitempty"`
	IssuedAt             time.Time  `json:"issued_at"`
	ExpiresAt            time.Time  `json:"expires_at"`
	MaxUses              int        `json:"max_uses,omitempty"`
	UsesRemaining        int        `json:"uses_remaining,omitempty"`
	ConsumptionLogPath   string     `json:"consumption_log_path,omitempty"`
	Revoked              bool       `json:"revoked"`
	RevokedAt            *time.Time `json:"revoked_at,omitempty"`
	Parent               string     `json:"parent,omitempty"`
	IssuedFromLLMSession bool       `json:"issued_from_llm_session"`
	// team member who issued this grant (HMACd — value-free invariant).
	MemberID string `json:"member_id,omitempty"`
	// Legacy compat — round-trip unchanged.
	Scopes []string `json:"scopes,omitempty"`
}

// GrantSpec carries parameters for Create.
type GrantSpec struct {
	Actor      string
	Connection string
	Capability string
	Command    string
	CWD        string
	TTL        time.Duration
	MaxUses    int
	// MemberID is the HMACd member ID from team context (value-free).
	MemberID string
}

// ListOpts controls which grants are returned by List.
type ListOpts struct {
	IncludeExpired bool
	IncludeRevoked bool
	ActorFilter    string
}

// FindRequest is the input to Find.
type FindRequest struct {
	Actor      string
	Connection string
	Capability string
	Command    []string
	CWD        string
}

// isReadClassCap mirrors the policy-engine read-class check.
func isReadClassCap(cap string) bool {
	switch cap {
	case "read", "export":
		return true
	}
	return strings.HasSuffix(cap, ".reveal") || strings.HasSuffix(cap, ".dump")
}

// --- UUID generation ---------------------------------------------------------

// newUUID generates a random UUID v4.
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

// --- Accessor key ------------------------------------------------------------

var (
	accessorKeyOnce sync.Once
	accessorKey     []byte
	accessorKeyErr  error
)

// loadOrCreateAccessorKey loads the per-installation HMAC key from disk,
// creating it (random 32 bytes, mode 0o600) if it does not exist.
func loadOrCreateAccessorKey(env func(string) string) ([]byte, error) {
	accessorKeyOnce.Do(func() {
		keyPath := paths.GrantAccessorKey(env)
		data, err := os.ReadFile(keyPath)
		if err == nil && len(data) == 32 {
			accessorKey = data
			return
		}
		// Create or recreate.
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			accessorKeyErr = fmt.Errorf("grant: generate accessor key: %w", err)
			return
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			accessorKeyErr = fmt.Errorf("grant: mkdir for accessor key: %w", err)
			return
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			accessorKeyErr = fmt.Errorf("grant: write accessor key: %w", err)
			return
		}
		_ = os.Chmod(keyPath, 0o600)
		accessorKey = key
	})
	return accessorKey, accessorKeyErr
}

// computeAccessor returns the HMAC-SHA256 of id using the installation key.
func computeAccessor(id string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(id))
	return hex.EncodeToString(mac.Sum(nil))
}

// --- Storage helpers ---------------------------------------------------------

// readGrants reads the grants JSON array from path.
// Returns an empty slice if the file does not exist.
func readGrants(path string) ([]Grant, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("grant: read %q: %w", path, err)
	}
	var gs []Grant
	if err := json.Unmarshal(data, &gs); err != nil {
		return nil, fmt.Errorf("grant: parse %q: %w", path, err)
	}
	return gs, nil
}

// writeGrants atomically writes grants to path with mode 0o600.
func writeGrants(path string, gs []Grant) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("grant: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(gs, "", " ")
	if err != nil {
		return fmt.Errorf("grant: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("grant: write tmp: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("grant: rename: %w", err)
	}
	return nil
}

// --- Public API --------------------------------------------------------------

// Create issues a new Grant from spec.
// IssuedFromLLMSession is set from llmcontext.IsLLMSession(env).
func Create(_ context.Context, spec GrantSpec, env func(string) string) (*Grant, error) {
	id, err := newUUID()
	if err != nil {
		return nil, fmt.Errorf("grant: generate id: %w", err)
	}

	key, err := loadOrCreateAccessorKey(env)
	if err != nil {
		return nil, err
	}
	accessor := computeAccessor(id, key)

	now := time.Now().UTC()
	ttl := spec.TTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	g := &Grant{
		ID:                   id,
		Accessor:             accessor,
		Actor:                spec.Actor,
		Connection:           spec.Connection,
		Capability:           spec.Capability,
		Command:              spec.Command,
		CWD:                  spec.CWD,
		IssuedAt:             now,
		ExpiresAt:            now.Add(ttl),
		MaxUses:              spec.MaxUses,
		UsesRemaining:        spec.MaxUses,
		IssuedFromLLMSession: llmcontext.IsLLMSession(env),
		MemberID:             spec.MemberID, // HMACd from team context
	}

	if spec.MaxUses > 0 {
		grantsDir := paths.GrantsDir(env)
		if err := os.MkdirAll(grantsDir, 0o700); err != nil {
			return nil, fmt.Errorf("grant: mkdir grants dir: %w", err)
		}
		g.ConsumptionLogPath = filepath.Join(grantsDir, id+".consumption.log")
	}

	// Persist.
	grantPath := paths.Grants(env)
	grants, err := readGrants(grantPath)
	if err != nil {
		return nil, err
	}
	grants = append(grants, *g)
	if err := writeGrants(grantPath, grants); err != nil {
		return nil, err
	}
	return g, nil
}

// List returns grants from path filtered by opts.
func List(_ context.Context, path string, opts ListOpts) ([]Grant, error) {
	grants, err := readGrants(path)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var result []Grant
	for _, g := range grants {
		if !opts.IncludeRevoked && g.Revoked {
			continue
		}
		if !opts.IncludeExpired && g.ExpiresAt.Before(now) {
			continue
		}
		if opts.ActorFilter != "" && g.Actor != opts.ActorFilter {
			continue
		}
		result = append(result, g)
	}
	return result, nil
}

// Revoke marks the grant with the given id as revoked and cascades to children.
// The operation is atomic (single write).
func Revoke(_ context.Context, path string, id string) error {
	grants, err := readGrants(path)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	found := false
	for i := range grants {
		if grants[i].ID == id {
			grants[i].Revoked = true
			grants[i].RevokedAt = &now
			found = true
		}
	}
	if !found {
		return fmt.Errorf("grant: id %q not found", id)
	}
	// Cascade to children.
	for i := range grants {
		if grants[i].Parent == id && !grants[i].Revoked {
			grants[i].Revoked = true
			grants[i].RevokedAt = &now
		}
	}
	return writeGrants(path, grants)
}

// Find searches for the first non-expired, non-revoked grant that matches req.
//
// grants issued from an LLM session are never returned for read-class
// capabilities.
// expired grants are never returned.
// revoked grants are never returned.
// MaxUses enforcement via flock + append-only consumption log.
func Find(_ context.Context, path string, req FindRequest) (*Grant, bool) {
	grants, err := readGrants(path)
	if err != nil {
		return nil, false
	}
	now := time.Now().UTC()

	for i := range grants {
		g := &grants[i]

		// skip revoked.
		if g.Revoked {
			continue
		}
		// skip expired.
		if g.ExpiresAt.Before(now) {
			continue
		}
		// LLM-issued grant denied for read-class capability.
		if g.IssuedFromLLMSession && isReadClassCap(req.Capability) {
			continue
		}

		// Match fields.
		if !grantFieldsMatch(g, req) {
			continue
		}

		// MaxUses enforcement.
		if g.MaxUses > 0 {
			if ok := consumeUse(g); !ok {
				continue
			}
		}

		return g, true
	}
	return nil, false
}

// grantFieldsMatch checks whether a grant's fields match the FindRequest.
func grantFieldsMatch(g *Grant, req FindRequest) bool {
	if req.Actor != "" && g.Actor != "" && g.Actor != req.Actor {
		return false
	}
	if req.Connection != "" && g.Connection != "" && g.Connection != req.Connection {
		return false
	}
	if req.Capability != "" && g.Capability != "" && g.Capability != req.Capability {
		return false
	}
	return true
}

// consumeUse tries to record a use in the consumption log.
// Returns true if the use was recorded (count < MaxUses), false if exhausted.
func consumeUse(g *Grant) bool {
	if g.ConsumptionLogPath == "" {
		// Fallback: use UsesRemaining (legacy path).
		if g.UsesRemaining <= 0 {
			return false
		}
		g.UsesRemaining--
		return true
	}
	return consumeUseLog(g)
}
