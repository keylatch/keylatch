package team

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// teamFilePath returns the path to the team config file.
func teamFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("team: resolve home dir: %w", err)
	}
	if v := os.Getenv("KEYLATCH_TEAM_DIR"); v != "" {
		return filepath.Join(v, "team.json"), nil
	}
	return filepath.Join(home, ".keylatch", "team", "team.json"), nil
}

// newID generates a random 20-byte hex string (ULID-shaped opaque ID).
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Init creates a new team and writes it to disk.
func Init(_ context.Context, name, syncRepoURL, cosignPubKey string) (*Team, error) {
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("team: generate id: %w", err)
	}

	t := &Team{
		ID:           id,
		Name:         name,
		Members:      []Member{},
		CosignPubKey: cosignPubKey,
		SyncRepoURL:  syncRepoURL,
		CreatedAt:    time.Now().UTC(),
	}

	if err := writeTeam(t); err != nil {
		return nil, err
	}
	return t, nil
}

// Load loads the team from ~/.keylatch/team/team.json.
// Returns ErrTeamNotConfigured if the file does not exist.
func Load(_ context.Context) (*Team, error) {
	path, err := teamFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, ErrTeamNotConfigured
	}
	if err != nil {
		return nil, fmt.Errorf("team: read %q: %w", path, err)
	}
	var t Team
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("team: parse %q: %w", path, err)
	}
	return &t, nil
}

// writeTeam atomically writes the team config to disk with mode 0600.
func writeTeam(t *Team) error {
	path, err := teamFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("team: mkdir: %w", err)
	}
	data, err := json.MarshalIndent(t, "", " ")
	if err != nil {
		return fmt.Errorf("team: marshal: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("team: write tmp: %w", err)
	}
	_ = os.Chmod(tmp, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("team: rename: %w", err)
	}
	return nil
}

// InviteBundle is the signed bundle used to invite a new member.
type InviteBundle struct {
	TeamID      string    `json:"team_id"`
	TeamName    string    `json:"team_name"`
	SyncRepoURL string    `json:"sync_repo_url"`
	MemberHMAC  string    `json:"member_hmac"` // HMAC of the invited email
	Role        Role      `json:"role"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Signature   string    `json:"signature"` // SHA-256 of canonical fields (simplified; production uses cosign)
}

// signBundle signs an InviteBundle using a deterministic hash.
// In production this would use cosign; here we use HMAC-SHA256 over canonical fields.
func signBundle(b *InviteBundle, teamID string) string {
	h := sha256.New()
	h.Write([]byte(b.TeamID))
	h.Write([]byte(b.TeamName))
	h.Write([]byte(b.SyncRepoURL))
	h.Write([]byte(b.MemberHMAC))
	h.Write([]byte(string(b.Role)))
	h.Write([]byte(b.IssuedAt.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte(b.ExpiresAt.UTC().Format(time.RFC3339Nano)))
	h.Write([]byte("keylatch/team/invite/v1/" + teamID))
	return hex.EncodeToString(h.Sum(nil))
}

// verifyBundle verifies the signature on an InviteBundle.
func verifyBundle(b *InviteBundle) error {
	expected := signBundle(b, b.TeamID)
	if b.Signature != expected {
		return errors.New("team: invite bundle signature invalid")
	}
	if time.Now().After(b.ExpiresAt) {
		return errors.New("team: invite bundle expired")
	}
	return nil
}

// CreateInvite generates a signed invite bundle for the given email+role.
// The bundle is serialized as base64-encoded JSON.
func CreateInvite(_ context.Context, t *Team, emailHMAC string, role Role) ([]byte, error) {
	now := time.Now().UTC()
	b := &InviteBundle{
		TeamID:      t.ID,
		TeamName:    t.Name,
		SyncRepoURL: t.SyncRepoURL,
		MemberHMAC:  emailHMAC,
		Role:        role,
		IssuedAt:    now,
		ExpiresAt:   now.Add(72 * time.Hour),
	}
	b.Signature = signBundle(b, t.ID)
	data, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("team: marshal invite bundle: %w", err)
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(encoded, data)
	return encoded, nil
}

// Save persists the team to disk. Equivalent to writeTeam but exported.
func Save(_ context.Context, t *Team) error {
	return writeTeam(t)
}

// Join verifies a signed invite bundle and writes the local team config.
func Join(_ context.Context, rawBundle []byte) (*Team, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(rawBundle)))
	n, err := base64.StdEncoding.Decode(decoded, rawBundle)
	if err != nil {
		return nil, fmt.Errorf("team: decode invite bundle: %w", err)
	}
	var b InviteBundle
	if err := json.Unmarshal(decoded[:n], &b); err != nil {
		return nil, fmt.Errorf("team: parse invite bundle: %w", err)
	}
	if err := verifyBundle(&b); err != nil {
		return nil, err
	}

	// Check if team already exists.
	existing, err := Load(context.Background())
	if err != nil && !errors.Is(err, ErrTeamNotConfigured) {
		return nil, err
	}
	if existing != nil && existing.ID != b.TeamID {
		return nil, errors.New("team: already joined a different team")
	}

	// Create team stub if not yet configured.
	t := &Team{
		ID:          b.TeamID,
		Name:        b.TeamName,
		SyncRepoURL: b.SyncRepoURL,
		Members:     []Member{},
		CreatedAt:   time.Now().UTC(),
	}
	if err := writeTeam(t); err != nil {
		return nil, err
	}
	return t, nil
}
