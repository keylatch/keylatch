package approval

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
)

// MinPassphraseLen is the shortest approver passphrase accepted.
const MinPassphraseLen = 12

// Errors returned by the approver key functions.
var (
	ErrNoApproverKey      = errors.New("approval: no approver key is configured")
	ErrWrongPassphrase    = errors.New("approval: approver passphrase is incorrect")
	ErrPassphraseTooShort = fmt.Errorf("approval: approver passphrase must be at least %d characters", MinPassphraseLen)
)

const approverKeyVersion = 1

// ApproverKey is the stored half of the approver credential: the public key
// and the Argon2id parameters that turn the approver passphrase into the
// private key. The private key and the passphrase are never stored.
type ApproverKey struct {
	Version   int    `json:"version"`
	PublicKey string `json:"public_key"`
	Salt      string `json:"salt"`
	Time      uint32 `json:"argon2_time"`
	MemoryKiB uint32 `json:"argon2_memory_kib"`
	Threads   uint8  `json:"argon2_threads"`
}

// Upper bounds keep a tampered key file from making Unlock allocate or spin
// without limit.
const (
	maxKDFTime      = 64
	maxKDFMemoryKiB = 4 << 20
)

// NewApproverKey derives a fresh approver key pair from passphrase using a
// new random salt and params.
func NewApproverKey(passphrase []byte, params argon2.Params) (*ApproverKey, ed25519.PrivateKey, error) {
	if len(passphrase) < MinPassphraseLen {
		return nil, nil, ErrPassphraseTooShort
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, fmt.Errorf("approval: generate salt: %w", err)
	}
	k := &ApproverKey{
		Version:   approverKeyVersion,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Time:      params.Time,
		MemoryKiB: params.Memory,
		Threads:   params.Threads,
	}
	priv, err := k.derive(passphrase)
	if err != nil {
		return nil, nil, err
	}
	k.PublicKey = base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	return k, priv, nil
}

// Unlock derives the private key from passphrase and checks it against the
// stored public key.
func (k *ApproverKey) Unlock(passphrase []byte) (ed25519.PrivateKey, error) {
	want, err := k.Public()
	if err != nil {
		return nil, err
	}
	priv, err := k.derive(passphrase)
	if err != nil {
		return nil, err
	}
	got := priv.Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		clear(priv)
		return nil, ErrWrongPassphrase
	}
	return priv, nil
}

// Public returns the approver public key.
func (k *ApproverKey) Public() (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("approval: approver key file has an invalid public key")
	}
	return pub, nil
}

func (k *ApproverKey) derive(passphrase []byte) (ed25519.PrivateKey, error) {
	if k.Version != approverKeyVersion {
		return nil, fmt.Errorf("approval: unsupported approver key version %d", k.Version)
	}
	if k.Time == 0 || k.Time > maxKDFTime || k.MemoryKiB == 0 || k.MemoryKiB > maxKDFMemoryKiB || k.Threads == 0 {
		return nil, errors.New("approval: approver key file has invalid key derivation parameters")
	}
	salt, err := base64.StdEncoding.DecodeString(k.Salt)
	if err != nil || len(salt) < 16 {
		return nil, errors.New("approval: approver key file has an invalid salt")
	}
	seed, err := argon2.Derive(passphrase, salt, argon2.Params{
		Time:    k.Time,
		Memory:  k.MemoryKiB,
		Threads: k.Threads,
		KeyLen:  ed25519.SeedSize,
	})
	if err != nil {
		return nil, fmt.Errorf("approval: derive approver key: %w", err)
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// LoadApproverKey reads the approver key file. It returns ErrNoApproverKey
// when the file does not exist.
func LoadApproverKey(path string) (*ApproverKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the approver key file under the keylatch config dir
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoApproverKey
	}
	if err != nil {
		return nil, fmt.Errorf("approval: read approver key: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var k ApproverKey
	if err := dec.Decode(&k); err != nil {
		return nil, fmt.Errorf("approval: parse approver key: %w", err)
	}
	if _, err := k.Public(); err != nil {
		return nil, err
	}
	return &k, nil
}

// SaveApproverKey writes k to path with mode 0o600, replacing any existing
// file atomically.
func SaveApproverKey(path string, k *ApproverKey) error {
	data, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return fmt.Errorf("approval: marshal approver key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("approval: create config dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".approver-*.tmp")
	if err != nil {
		return fmt.Errorf("approval: write approver key: %w", err)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // removed only when the rename did not happen
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("approval: write approver key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("approval: write approver key: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return fmt.Errorf("approval: write approver key: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("approval: write approver key: %w", err)
	}
	return nil
}
