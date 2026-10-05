package team

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/keylatch/keylatch/internal/team/bundlesig"
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
	if err := checkUniqueMembers(&t); err != nil {
		return nil, fmt.Errorf("team: %q: %w", path, err)
	}
	return &t, nil
}

// ErrAlreadyJoined is returned by Join when a local team file exists; it is
// never replaced, so its members and pinned keys cannot be reset by an
// invite.
var ErrAlreadyJoined = errors.New("team: this machine already has a team configured; remove it explicitly before joining again")

// ErrDuplicateMember is returned for a roster that lists one member ID more
// than once. Authorization looks a member up by ID, so a duplicate could let
// a check pass against one entry while a change lands on another.
var ErrDuplicateMember = errors.New("team: member ID appears more than once")

func checkUniqueMembers(t *Team) error {
	seen := make(map[string]bool, len(t.Members))
	for _, m := range t.Members {
		if seen[m.ID] {
			return fmt.Errorf("%w: %q", ErrDuplicateMember, m.ID)
		}
		seen[m.ID] = true
	}
	return nil
}

// writeTeam atomically writes the team config to disk with mode 0600.
func writeTeam(t *Team) error {
	if err := checkUniqueMembers(t); err != nil {
		return err
	}
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
	Signature   string    `json:"signature"` // Ed25519 by the team's invite signing key
}

const inviteDomain = "keylatch/team/invite/v2"

// inviteKeyFile holds the invite signing key next to team.json.
const inviteKeyFile = "invite-signing.key"

func inviteMessage(b *InviteBundle) []byte {
	return bundlesig.Message(inviteDomain,
		b.TeamID,
		b.TeamName,
		b.SyncRepoURL,
		b.MemberHMAC,
		string(b.Role),
		b.IssuedAt.UTC().Format(time.RFC3339Nano),
		b.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
}

// verifyBundle checks an invite against the team's invite public key.
func verifyBundle(b *InviteBundle, teamKey string) error {
	pub, err := bundlesig.ParsePublicKey(teamKey)
	if err != nil {
		return fmt.Errorf("team: invite needs the team's invite public key (shown by `keylatch team invite`): %w", err)
	}
	if err := bundlesig.Verify(pub, inviteMessage(b), b.Signature); err != nil {
		if errors.Is(err, bundlesig.ErrUnsigned) || errors.Is(err, bundlesig.ErrLegacySignature) {
			return fmt.Errorf("team: %w; ask a team owner to re-issue it with `keylatch team invite`", err)
		}
		return fmt.Errorf("team: invite %w", err)
	}
	if time.Now().After(b.ExpiresAt) {
		return errors.New("team: invite bundle expired")
	}
	return nil
}

// inviteSigningKey returns this machine's invite signing key for t. A team
// without an invite key gets one on first use; a team whose key was created
// elsewhere can only issue invites from the machine that holds it.
func inviteSigningKey(t *Team) (ed25519.PrivateKey, error) {
	teamPath, err := teamFilePath()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Dir(teamPath), inviteKeyFile)
	priv, err := bundlesig.LoadKeyFile(path)
	switch {
	case err == nil:
		pub := bundlesig.EncodePublicKey(priv.Public().(ed25519.PublicKey))
		if t.InvitePubKey != "" && t.InvitePubKey != pub {
			return nil, fmt.Errorf("team: invite signing key %q does not match the team's invite public key", path)
		}
		t.InvitePubKey = pub
		return priv, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("team: load invite signing key: %w", err)
	case t.InvitePubKey != "":
		return nil, errors.New("team: this machine does not hold the team's invite signing key; issue invites from the team owner's machine")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("team: mkdir: %w", err)
	}
	priv, err = bundlesig.CreateKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("team: %w", err)
	}
	t.InvitePubKey = bundlesig.EncodePublicKey(priv.Public().(ed25519.PublicKey))
	return priv, nil
}

// CreateInvite generates a signed invite bundle for the given email+role.
// The bundle is serialized as base64-encoded JSON. When this call creates
// the team's invite key, t gains InvitePubKey and is saved.
func CreateInvite(_ context.Context, t *Team, emailHMAC string, role Role) ([]byte, error) {
	hadKey := t.InvitePubKey != ""
	priv, err := inviteSigningKey(t)
	if err != nil {
		return nil, err
	}
	if !hadKey {
		if err := writeTeam(t); err != nil {
			return nil, err
		}
	}
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
	b.Signature = bundlesig.Sign(priv, inviteMessage(b))
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

// Join verifies a signed invite bundle against teamKey, the team's invite
// public key obtained from the inviter out of band, and writes the local
// team config.
func Join(_ context.Context, rawBundle []byte, teamKey string) (*Team, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(rawBundle)))
	n, err := base64.StdEncoding.Decode(decoded, rawBundle)
	if err != nil {
		return nil, fmt.Errorf("team: decode invite bundle: %w", err)
	}
	var b InviteBundle
	if err := json.Unmarshal(decoded[:n], &b); err != nil {
		return nil, fmt.Errorf("team: parse invite bundle: %w", err)
	}
	if err := verifyBundle(&b, teamKey); err != nil {
		return nil, err
	}
	pub, _ := bundlesig.ParsePublicKey(teamKey)
	teamKey = bundlesig.EncodePublicKey(pub)

	// Check if team already exists.
	existing, err := Load(context.Background())
	if err != nil && !errors.Is(err, ErrTeamNotConfigured) {
		return nil, err
	}
	if existing != nil && existing.ID != b.TeamID {
		return nil, errors.New("team: already joined a different team")
	}
	if existing != nil && existing.InvitePubKey != "" && existing.InvitePubKey != teamKey {
		return nil, errors.New("team: invite key differs from the key this team was joined with")
	}
	if existing != nil {
		return nil, ErrAlreadyJoined
	}

	// Create team stub if not yet configured.
	t := &Team{
		ID:           b.TeamID,
		Name:         b.TeamName,
		SyncRepoURL:  b.SyncRepoURL,
		InvitePubKey: teamKey,
		Members:      []Member{},
		CreatedAt:    time.Now().UTC(),
	}
	if err := writeTeam(t); err != nil {
		return nil, err
	}
	return t, nil
}
