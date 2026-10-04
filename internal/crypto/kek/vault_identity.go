package kek

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// InsecureFileKEKEnv is the environment equivalent of --insecure-file-kek.
const InsecureFileKEKEnv = "KEYLATCH_INSECURE_FILE_KEK"

const identitySize = 32

var (
	// ErrNoOSKeyring means no usable OS keyring could hold the vault identity.
	ErrNoOSKeyring = errors.New("kek: no usable OS keyring")

	// ErrIdentityNotFound means the OS keyring has no item for the account.
	ErrIdentityNotFound = errors.New("kek: vault identity not found in OS keyring")

	accountPattern = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
)

// IdentityStore keeps the file backend's root identity in an OS keyring.
type IdentityStore interface {
	Name() string
	Load(account string) ([]byte, error)
	Store(account string, identity []byte) error
	Delete(account string) error
}

// IdentityLocation reports where the vault identity currently lives.
type IdentityLocation int

const (
	IdentityMissing IdentityLocation = iota
	IdentityInKeyring
	// IdentityInFileAcknowledged is a plaintext identity the user opted into.
	IdentityInFileAcknowledged
	// IdentityInFileUnacknowledged is a plaintext identity from an older
	// install that has not been moved into a keyring or acknowledged.
	IdentityInFileUnacknowledged
)

// VaultIdentity locates the 32-byte root identity the file backend KEK is
// derived from. The identity lives either in an OS keyring, referenced by the
// sidecar at RefPath, or in the plaintext file at Path.
type VaultIdentity struct {
	Path  string
	Store IdentityStore
}

type identityRef struct {
	Store   string `json:"store"`
	Account string `json:"account"`
}

// RefPath is the non-secret sidecar naming the keyring item.
func (v VaultIdentity) RefPath() string { return v.Path + ".keyring" }

// InsecureMarkerPath records the user's opt-in to a plaintext identity file.
func (v VaultIdentity) InsecureMarkerPath() string { return v.Path + ".insecure" }

// InsecureFileKEKRequested reports whether the environment opts into a
// plaintext identity file.
func InsecureFileKEKRequested(lookup func(string) string) bool {
	switch strings.ToLower(strings.TrimSpace(lookup(InsecureFileKEKEnv))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// Location reports where the identity lives and whether a plaintext copy is
// still on disk.
func (v VaultIdentity) Location() (loc IdentityLocation, plaintextOnDisk bool, err error) {
	refExists, err := regularFileExists(v.RefPath())
	if err != nil {
		return IdentityMissing, false, err
	}
	fileExists, err := regularFileExists(v.Path)
	if err != nil {
		return IdentityMissing, false, err
	}
	switch {
	case refExists:
		return IdentityInKeyring, fileExists, nil
	case fileExists:
		ack, err := regularFileExists(v.InsecureMarkerPath())
		if err != nil {
			return IdentityMissing, true, err
		}
		if ack {
			return IdentityInFileAcknowledged, true, nil
		}
		return IdentityInFileUnacknowledged, true, nil
	}
	return IdentityMissing, false, nil
}

// Provision creates a fresh identity. Without insecure it goes into the OS
// keyring and fails with ErrNoOSKeyring when none is usable; with insecure it
// is written to Path and the opt-in is recorded.
func (v VaultIdentity) Provision(insecure bool) error {
	identity := make([]byte, identitySize)
	if _, err := rand.Read(identity); err != nil {
		return fmt.Errorf("generate identity: %w", err)
	}
	defer zero(identity)

	if insecure {
		if err := writeFileAtomic(v.Path, identity); err != nil {
			return fmt.Errorf("write identity %q: %w", v.Path, err)
		}
		return writeFileAtomic(v.InsecureMarkerPath(), nil)
	}
	return v.storeInKeyring(identity)
}

// Load returns the identity bytes. When a keyring reference exists the
// plaintext file is never consulted, so a stale or planted file cannot
// override the keyring item.
func (v VaultIdentity) Load() ([]byte, error) {
	ref, ok, err := v.readRef()
	if err != nil {
		return nil, err
	}
	if !ok {
		return readIdentityFile(v.Path)
	}
	if v.Store == nil || v.Store.Name() != ref.Store {
		return nil, fmt.Errorf("%w: vault identity is held in %s, which is not reachable from this session", ErrKEKUnavailable, ref.Store)
	}
	identity, err := v.Store.Load(ref.Account)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrKEKUnavailable, ref.Store, err)
	}
	return identity, nil
}

// KEK derives the wrapping key for a keyring with the given salt.
func (v VaultIdentity) KEK(salt []byte) (KEK, error) {
	identity, err := v.Load()
	if err != nil {
		return nil, err
	}
	defer zero(identity)
	return IdentityKEK(identity, salt)
}

// MigrateToKeyring moves a plaintext identity into the OS keyring, verifies
// the read-back, then removes the file and any opt-in marker. It also finishes
// a migration interrupted after the reference was written. It reports whether
// a plaintext file was removed.
func (v VaultIdentity) MigrateToKeyring() (bool, error) {
	loc, onDisk, err := v.Location()
	if err != nil || !onDisk {
		return false, err
	}
	if v.Store == nil {
		return false, ErrNoOSKeyring
	}
	fileIdentity, err := readIdentityFile(v.Path)
	if err != nil {
		if stillThere, _ := regularFileExists(v.Path); !stillThere {
			return false, nil // another process finished the migration
		}
		return false, err
	}
	defer zero(fileIdentity)

	if loc == IdentityInKeyring {
		held, err := v.Load()
		if err != nil {
			return false, err
		}
		defer zero(held)
		if subtle.ConstantTimeCompare(held, fileIdentity) != 1 {
			return false, fmt.Errorf("plaintext identity %q differs from the OS keyring item; left in place", v.Path)
		}
	} else if err := v.storeInKeyring(fileIdentity); err != nil {
		return false, err
	}

	if err := removeIfExists(v.Path); err != nil {
		return false, err
	}
	if err := removeIfExists(v.InsecureMarkerPath()); err != nil {
		return true, err
	}
	return true, nil
}

// Acknowledge records the opt-in for an existing plaintext identity.
func (v VaultIdentity) Acknowledge() error {
	return writeFileAtomic(v.InsecureMarkerPath(), nil)
}

// Remove deletes the identity wherever it lives, including the keyring item.
func (v VaultIdentity) Remove() error {
	ref, ok, err := v.readRef()
	if err != nil {
		return err
	}
	if ok && v.Store != nil && v.Store.Name() == ref.Store {
		if err := v.Store.Delete(ref.Account); err != nil && !errors.Is(err, ErrIdentityNotFound) {
			return fmt.Errorf("delete keyring item: %w", err)
		}
	}
	for _, p := range []string{v.RefPath(), v.Path, v.InsecureMarkerPath()} {
		if err := removeIfExists(p); err != nil {
			return err
		}
	}
	return nil
}

func (v VaultIdentity) storeInKeyring(identity []byte) error {
	if v.Store == nil {
		return ErrNoOSKeyring
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("generate keyring account: %w", err)
	}
	account := "vault-" + hex.EncodeToString(suffix)

	if err := v.Store.Store(account, identity); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrNoOSKeyring, v.Store.Name(), err)
	}
	held, err := v.Store.Load(account)
	if err != nil {
		_ = v.Store.Delete(account)
		return fmt.Errorf("%w: %s read-back: %v", ErrNoOSKeyring, v.Store.Name(), err)
	}
	defer zero(held)
	if subtle.ConstantTimeCompare(held, identity) != 1 {
		_ = v.Store.Delete(account)
		return fmt.Errorf("%w: %s returned different bytes on read-back", ErrNoOSKeyring, v.Store.Name())
	}

	b, err := json.Marshal(identityRef{Store: v.Store.Name(), Account: account})
	if err != nil {
		return err
	}
	if err := writeFileAtomic(v.RefPath(), b); err != nil {
		_ = v.Store.Delete(account)
		return fmt.Errorf("write keyring reference %q: %w", v.RefPath(), err)
	}
	return nil
}

func (v VaultIdentity) readRef() (identityRef, bool, error) {
	b, err := os.ReadFile(v.RefPath())
	if errors.Is(err, os.ErrNotExist) {
		return identityRef{}, false, nil
	}
	if err != nil {
		return identityRef{}, false, fmt.Errorf("%w: read %q: %v", ErrKEKUnavailable, v.RefPath(), err)
	}
	var ref identityRef
	if err := json.Unmarshal(b, &ref); err != nil || ref.Store == "" || !accountPattern.MatchString(ref.Account) {
		return identityRef{}, false, fmt.Errorf("%w: malformed keyring reference %q", ErrKEKUnavailable, v.RefPath())
	}
	return ref, true, nil
}

func decodeIdentity(out []byte) ([]byte, error) {
	s := strings.TrimSpace(string(out))
	if s == "" {
		return nil, ErrIdentityNotFound
	}
	identity, err := hex.DecodeString(s)
	if err != nil || len(identity) != identitySize {
		return nil, errors.New("keyring item is not a hex-encoded 32-byte identity")
	}
	return identity, nil
}

func validAccount(account string) error {
	if !accountPattern.MatchString(account) {
		return fmt.Errorf("invalid keyring account %q", account)
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func regularFileExists(p string) (bool, error) {
	info, err := os.Stat(p)
	if err == nil {
		return !info.IsDir(), nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat %q: %w", p, err)
}

func removeIfExists(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove %q: %w", p, err)
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
