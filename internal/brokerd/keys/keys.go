// Package keys is the broker's key hierarchy. A device root, handed to the
// daemon by the service manager, wraps one broker master key (BMK); every
// other key is derived from the BMK or stored wrapped by it. Nothing is ever
// written unwrapped, and key material lives in locked memory.
//
//	device root ─ BMK ─┬─ store KEK per partition   HKDF(BMK, salt, "keylatch/store/v1")
//	                   ├─ backend-credential KEK    HKDF(BMK, salt, "keylatch/backend-cred/v1")
//	                   ├─ audit chain seed and seal HKDF(BMK, salt, "keylatch/audit/v1", ".../audit-seal/v1")
//	                   └─ Ed25519 keys (token signing, audit anchor, policy signing,
//	                      machine CA): random, wrapped by the BMK
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// CredentialName is the name of the systemd credential that carries the device
// root.
const CredentialName = "keylatch-root"

// The info strings are HKDF domain separators, not credentials.
const (
	infoStore       = "keylatch/store/v1"
	infoBackendCred = "keylatch/backend-cred/v1"
	infoAudit       = "keylatch/audit/v1"
	infoAuditSeal   = "keylatch/audit-seal/v1"
	infoTokenHMAC   = "keylatch/token-hmac/v1" //nolint:gosec // G101: a domain separator
	infoRootWrap    = "keylatch/root-wrap/v1"
	infoSyncHMAC    = "keylatch/sync-hmac/v1"    //nolint:gosec // G101: a domain separator
	infoServiceHMAC = "keylatch/service-hmac/v1" //nolint:gosec // G101: a domain separator

	rootMinLen = 32
	keyLen     = 32
	wrapFormat = 1
	bmkFile    = "bmk.wrapped"
	stagedExt  = ".new"
)

// Name identifies one of the hierarchy's Ed25519 keys.
type Name string

// The Ed25519 keys the hierarchy holds.
const (
	TokenSigning  Name = "token-signing"
	AuditAnchor   Name = "audit-anchor"
	PolicySigning Name = "policy-signing"
	MachineCA     Name = "machine-ca"
)

var childNames = []Name{TokenSigning, AuditAnchor, PolicySigning, MachineCA}

var (
	// ErrNoRoot means the device root credential is missing or too short.
	ErrNoRoot = errors.New("keys: the device root credential is missing or shorter than 32 bytes")
	// ErrWrongRoot means the device root does not open the stored master key.
	ErrWrongRoot = errors.New("keys: the device root does not open the broker master key")
	// ErrUnknownKey means a wrapped key names a master key this daemon does not hold.
	ErrUnknownKey = errors.New("keys: the key is wrapped by an unknown master key")
)

// KEKFunc returns the store key-encryption key of a partition.
type KEKFunc func(partition string) []byte

// Rewrap moves data keys from the old master key to the staged one, tagging them
// newKID. It runs while the hierarchy is locked, so it must not call back into
// it.
type Rewrap func(oldKEK, newKEK KEKFunc, newKID string) error

type wrapped struct {
	V     int    `json:"v"`
	KID   string `json:"kid"`
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
}

// LoadRoot reads the device root from the credentials directory systemd set up
// for the unit ($CREDENTIALS_DIRECTORY).
func LoadRoot(credentialsDir string) ([]byte, error) {
	if credentialsDir == "" {
		return nil, ErrNoRoot
	}
	b, err := os.ReadFile(filepath.Join(credentialsDir, CredentialName)) //nolint:gosec // G304: the credentials directory is set by systemd
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoRoot, err)
	}
	if len(b) < rootMinLen {
		clear(b)
		return nil, ErrNoRoot
	}
	return b, nil
}

// Hierarchy is an open key hierarchy.
type Hierarchy struct {
	dir      string
	rootWrap *secret
	lock     bool

	mu         sync.RWMutex
	bmk        *secret
	kid        string
	pending    *secret
	pendingKID string
	signers    map[Name]*secret
}

// Open opens the hierarchy stored in dir, creating the master key when the
// directory is new. root is the device root. With lock set, key pages must be
// lockable into memory or Open fails.
func Open(dir string, root []byte, lock bool) (*Hierarchy, error) {
	if len(root) < rootMinLen {
		return nil, ErrNoRoot
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	h := &Hierarchy{dir: dir, lock: lock, signers: map[Name]*secret{}}
	var err error
	if h.rootWrap, err = newSecret(derive(root, nil, infoRootWrap), lock); err != nil {
		return nil, err
	}
	fail := func(err error) (*Hierarchy, error) { h.Close(); return nil, err }

	switch h.bmk, h.kid, err = h.loadBMK(bmkFile); {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		buf := make([]byte, keyLen)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return fail(fmt.Errorf("keys: generate master key: %w", err))
		}
		if h.bmk, err = newSecret(buf, lock); err != nil {
			return fail(err)
		}
		h.kid = kidOf(h.bmk.b)
		if err := h.writeBMK(bmkFile, h.bmk, h.kid); err != nil {
			return fail(err)
		}
	default:
		return fail(err)
	}
	if p, kid, err := h.loadBMK(bmkFile + stagedExt); err == nil {
		h.pending, h.pendingKID = p, kid
	}
	return h, nil
}

// Close zeroes and unlocks every key held in memory.
func (h *Hierarchy) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range []*secret{h.rootWrap, h.bmk, h.pending} {
		s.destroy()
	}
	for _, s := range h.signers {
		s.destroy()
	}
	h.signers = map[Name]*secret{}
}

// Locked reports whether the hierarchy's keys sit in locked memory.
func (h *Hierarchy) Locked() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.bmk != nil && h.bmk.locked
}

// KeyID names the current master key.
func (h *Hierarchy) KeyID() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.kid
}

// Pending reports that a master key rotation was staged but not committed.
func (h *Hierarchy) Pending() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pending != nil
}

// PendingKeyID names the staged master key of a rotation, or "" when none is
// staged.
func (h *Hierarchy) PendingKeyID() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pendingKID
}

// StoreKEK returns the store key-encryption key of a partition and the id of
// the master key it comes from.
func (h *Hierarchy) StoreKEK(partition string) (kid string, key []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.kid, derive(h.bmk.b, salt("store", partition), infoStore)
}

// KEKFor returns the store key-encryption key of a partition under the master
// key named kid: the current one, or the staged one during a rotation.
func (h *Hierarchy) KEKFor(kid, partition string) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	m := h.masterFor(kid)
	if m == nil {
		return nil, ErrUnknownKey
	}
	return derive(m.b, salt("store", partition), infoStore), nil
}

// BackendCredentialKEK returns the key that wraps backend credentials.
func (h *Hierarchy) BackendCredentialKEK() []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return derive(h.bmk.b, salt("backend-cred", ""), infoBackendCred)
}

// AuditKeys returns the audit chain seed and the key audit events are sealed
// with.
func (h *Hierarchy) AuditKeys() (seed, seal []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := salt("audit", "")
	return derive(h.bmk.b, s, infoAudit), derive(h.bmk.b, s, infoAuditSeal)
}

// Signer returns the Ed25519 key called name, creating it on first use.
func (h *Hierarchy) Signer(name Name) (ed25519.PrivateKey, error) {
	if !slices.Contains(childNames, name) {
		return nil, fmt.Errorf("keys: unknown key %q", name)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if s, ok := h.signers[name]; ok {
		return ed25519.NewKeyFromSeed(s.b), nil
	}
	seed, err := h.loadChild(name)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, ed25519.SeedSize)
		if _, err = io.ReadFull(rand.Reader, seed); err == nil {
			err = h.writeChild(name, seed, h.bmk, h.kid, "")
		}
	}
	if err != nil {
		clear(seed)
		return nil, err
	}
	s, err := newSecret(seed, h.lock)
	if err != nil {
		return nil, err
	}
	h.signers[name] = s
	return ed25519.NewKeyFromSeed(s.b), nil
}

// Public returns the public half of the Ed25519 key called name.
func (h *Hierarchy) Public(name Name) (ed25519.PublicKey, error) {
	k, err := h.Signer(name)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return k.Public().(ed25519.PublicKey), nil
}

// TokenKey returns the 32-byte key the daemon's own session tickets are
// authenticated with.
func (h *Hierarchy) TokenKey() ([]byte, error) { return h.TokenKeyFor("") }

// TokenKeyFor returns the 32-byte key gateway session tokens of one partition
// are authenticated with. Every partition has its own, so a token minted for
// one user's gateway is worthless at another's, even though the gateways listen
// on loopback ports any local user can reach. The key is derived from the
// token-signing key, so the signing seed is never used directly as a MAC key.
func (h *Hierarchy) TokenKeyFor(partition string) ([]byte, error) {
	k, err := h.Signer(TokenSigning)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return derive(k.Seed(), salt("token", partition), infoTokenHMAC), nil
}

// KeyPolicyKeyFor seals one partition's key-operation allowlist independently of session tokens.
func (h *Hierarchy) KeyPolicyKeyFor(partition string) ([]byte, error) {
	k, err := h.Signer(TokenSigning)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return derive(k.Seed(), salt("key-policy", partition), "keylatch/key-policy-hmac/v1"), nil
}

// ApprovalSignerFor signs presence-verified decisions for exactly one partition.
func (h *Hierarchy) ApprovalSignerFor(partition string) (ed25519.PrivateKey, error) {
	k, err := h.Signer(TokenSigning)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	seed := derive(k.Seed(), salt("approval", partition), "keylatch/approval-signing/v1")
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// SyncKeyFor returns the 32-byte key the keyed hashes of one partition's sync
// writes are computed with. The daemon alone holds it, so a value is compared
// with what was written without a plain hash ever existing.
func (h *Hierarchy) SyncKeyFor(partition string) ([]byte, error) {
	k, err := h.Signer(TokenSigning)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return derive(k.Seed(), salt("sync", partition), infoSyncHMAC), nil
}

// ServiceKeyFor returns the 32-byte key service capabilities of one partition
// are hashed with before they are stored.
func (h *Hierarchy) ServiceKeyFor(partition string) ([]byte, error) {
	k, err := h.Signer(TokenSigning)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	return derive(k.Seed(), salt("service", partition), infoServiceHMAC), nil
}

// Rotate replaces the master key. Every wrapped child key is rewrapped, and
// rewrap is called with the old and the new store KEK functions so the store
// can rewrap its data keys; no stored value is re-encrypted. The new key is
// staged on disk before rewrap runs and committed after it succeeds, so an
// interrupted rotation is finished with Resume.
func (h *Hierarchy) Rotate(rewrap Rewrap) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending != nil {
		return errors.New("keys: a rotation is already staged; resume it first")
	}
	buf := make([]byte, keyLen)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return fmt.Errorf("keys: generate master key: %w", err)
	}
	next, err := newSecret(buf, h.lock)
	if err != nil {
		return err
	}
	nextKID := kidOf(next.b)
	for _, name := range childNames {
		seed, err := h.loadChild(name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			next.destroy()
			return err
		}
		err = h.writeChild(name, seed, next, nextKID, stagedExt)
		clear(seed)
		if err != nil {
			next.destroy()
			return err
		}
	}
	if err := h.writeBMK(bmkFile+stagedExt, next, nextKID); err != nil {
		next.destroy()
		return err
	}
	h.pending, h.pendingKID = next, nextKID
	return h.finish(rewrap)
}

// Resume finishes a rotation that was staged but not committed.
func (h *Hierarchy) Resume(rewrap Rewrap) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pending == nil {
		return nil
	}
	return h.finish(rewrap)
}

func (h *Hierarchy) finish(rewrap Rewrap) error {
	if rewrap != nil {
		oldKEK := func(p string) []byte { return derive(h.bmk.b, salt("store", p), infoStore) }
		newKEK := func(p string) []byte { return derive(h.pending.b, salt("store", p), infoStore) }
		if err := rewrap(oldKEK, newKEK, h.pendingKID); err != nil {
			return fmt.Errorf("keys: rewrap data keys: %w", err)
		}
	}
	for _, name := range childNames {
		src := filepath.Join(h.dir, string(name)+".key"+stagedExt)
		if _, err := os.Stat(src); err != nil {
			continue
		}
		if err := os.Rename(src, filepath.Join(h.dir, string(name)+".key")); err != nil {
			return fmt.Errorf("keys: commit rotation: %w", err)
		}
	}
	if err := os.Rename(filepath.Join(h.dir, bmkFile+stagedExt), filepath.Join(h.dir, bmkFile)); err != nil {
		return fmt.Errorf("keys: commit rotation: %w", err)
	}
	h.bmk.destroy()
	h.bmk, h.kid, h.pending, h.pendingKID = h.pending, h.pendingKID, nil, ""
	return nil
}

func (h *Hierarchy) masterFor(kid string) *secret {
	switch {
	case kid == h.kid:
		return h.bmk
	case h.pending != nil && kid == h.pendingKID:
		return h.pending
	}
	return nil
}

func (h *Hierarchy) loadBMK(file string) (*secret, string, error) {
	var w wrapped
	if err := readJSON(filepath.Join(h.dir, file), &w); err != nil {
		return nil, "", err
	}
	plain, err := open(h.rootWrap.b, w, bmkAAD(w.KID))
	if err != nil {
		return nil, "", ErrWrongRoot
	}
	s, err := newSecret(plain, h.lock)
	if err != nil {
		return nil, "", err
	}
	if kidOf(s.b) != w.KID {
		s.destroy()
		return nil, "", ErrWrongRoot
	}
	return s, w.KID, nil
}

func (h *Hierarchy) writeBMK(file string, m *secret, kid string) error {
	w, err := seal(h.rootWrap.b, m.b, kid, bmkAAD(kid))
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(h.dir, file), w)
}

func (h *Hierarchy) loadChild(name Name) ([]byte, error) {
	var w wrapped
	if err := readJSON(filepath.Join(h.dir, string(name)+".key"), &w); err != nil {
		return nil, err
	}
	m := h.masterFor(w.KID)
	if m == nil {
		return nil, ErrUnknownKey
	}
	seed, err := open(m.b, w, childAAD(name, w.KID))
	if err != nil {
		return nil, fmt.Errorf("keys: open %s: %w", name, err)
	}
	return seed, nil
}

func (h *Hierarchy) writeChild(name Name, seed []byte, m *secret, kid, ext string) error {
	w, err := seal(m.b, seed, kid, childAAD(name, kid))
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(h.dir, string(name)+".key"+ext), w)
}

func bmkAAD(kid string) []byte { return []byte("keylatch/bmk/v1\x00" + kid) }

func childAAD(name Name, kid string) []byte {
	return []byte("keylatch/child/v1\x00" + string(name) + "\x00" + kid)
}

func kidOf(master []byte) string {
	h := sha256.Sum256(append([]byte("keylatch/kid/v1\x00"), master...))
	return hex.EncodeToString(h[:8])
}

func salt(purpose, partition string) []byte {
	h := sha256.Sum256([]byte("keylatch/salt/v1\x00" + purpose + "\x00" + partition))
	return h[:]
}

func derive(secret, salt []byte, info string) []byte {
	out := make([]byte, keyLen)
	_, _ = io.ReadFull(hkdf.New(sha256.New, secret, salt, []byte(info)), out)
	return out
}

func seal(key, plain []byte, kid string, aad []byte) (wrapped, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return wrapped{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return wrapped{}, err
	}
	return wrapped{V: wrapFormat, KID: kid, Nonce: nonce, CT: aead.Seal(nil, nonce, plain, aad)}, nil
}

func open(key []byte, w wrapped, aad []byte) ([]byte, error) {
	if w.V != wrapFormat {
		return nil, fmt.Errorf("keys: unsupported wrap format %d", w.V)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(w.Nonce) != aead.NonceSize() {
		return nil, errors.New("keys: malformed wrapped key")
	}
	return aead.Open(nil, w.Nonce, w.CT, aad)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path is inside the hierarchy directory
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("keys: %s: %w", filepath.Base(path), err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("keys: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("keys: %w", err)
	}
	return nil
}

// Files lists the key files in the hierarchy directory, for tests and doctor.
func (h *Hierarchy) Files() []string {
	entries, _ := os.ReadDir(h.dir)
	var out []string
	for _, e := range entries {
		if !e.IsDir() && !strings.HasSuffix(e.Name(), ".tmp") {
			out = append(out, e.Name())
		}
	}
	return out
}
