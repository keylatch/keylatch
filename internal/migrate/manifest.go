package migrate

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/argon2"
)

// ErrNotFound is what a Store returns for a path it does not hold.
var ErrNotFound = errors.New("migrate: item not found")

// ErrUnreadable is what a Store returns for an item it holds but never hands
// back, such as a secret inside the system broker. Import leaves it alone.
var ErrUnreadable = errors.New("migrate: the backend holds the item but does not return it")

// Flusher is a Store that batches its writes; Import flushes once at the end.
type Flusher interface {
	Flush(ctx context.Context) error
}

// Store is the backend side of an import or a verification.
type Store interface {
	// Get returns the value at path, or ErrNotFound. The caller wipes it.
	Get(ctx context.Context, path string) ([]byte, error)
	Put(ctx context.Context, path string, value []byte) error
}

// KDF holds the Argon2id parameters and salt the manifest key derives from.
type KDF struct {
	Alg       string `json:"alg"`
	Salt      string `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// Floors for a manifest read from disk, so a doctored file cannot make the
// passphrase cheap to guess.
const (
	minKDFTime   = 2
	minKDFMemory = 19 * 1024
	maxKDFMemory = 1 << 20
	maxKDFTime   = 16
)

// NewKDF returns parameters with a fresh salt.
func NewKDF() (KDF, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return KDF{}, err
	}
	return KDF{Alg: "argon2id", Salt: base64.StdEncoding.EncodeToString(salt), Time: 3, MemoryKiB: 64 * 1024, Threads: 4}, nil
}

func (k KDF) validate() error {
	if k.Alg != "argon2id" || k.Time < minKDFTime || k.Time > maxKDFTime ||
		k.MemoryKiB < minKDFMemory || k.MemoryKiB > maxKDFMemory || k.Threads == 0 {
		return errors.New("migrate manifest: the key derivation parameters are not acceptable")
	}
	if s, err := base64.StdEncoding.DecodeString(k.Salt); err != nil || len(s) < 16 {
		return errors.New("migrate manifest: the salt is malformed")
	}
	return nil
}

// Key derives the manifest key from the recovery passphrase.
func (k KDF) Key(passphrase []byte) ([]byte, error) {
	if err := k.validate(); err != nil {
		return nil, err
	}
	if len(passphrase) == 0 {
		return nil, errors.New("migrate manifest: a recovery passphrase is required")
	}
	salt, _ := base64.StdEncoding.DecodeString(k.Salt)
	return argon2.IDKey(passphrase, salt, k.Time, k.MemoryKiB, k.Threads, 32), nil
}

// MAC is the hex HMAC-SHA256 of value under key.
func MAC(key, value []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(value)
	return hex.EncodeToString(m.Sum(nil))
}

// Manifest lists, per item, the keyed hash of the value it held when imported.
type Manifest struct {
	Version int            `json:"version"`
	KDF     KDF            `json:"kdf"`
	Items   []ManifestItem `json:"items"`
}

// ManifestItem is one entry of a manifest.
type ManifestItem struct {
	Path string `json:"path"`
	MAC  string `json:"mac"`
}

// ParseManifest decodes a manifest and checks its parameters.
func ParseManifest(data []byte) (Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("migrate manifest: %w", err)
	}
	if m.Version != 1 {
		return Manifest{}, errors.New("migrate manifest: version must be 1")
	}
	return m, m.KDF.validate()
}

// Report is the outcome of checking a manifest against a backend. It holds
// paths and counts only.
type Report struct {
	OK       int      `json:"ok"`
	Failed   []string `json:"failed"`
	Missing  []string `json:"missing"`
	Duration string   `json:"duration"`
}

// Verify fetches every manifest item and compares keyed hashes. A value that
// differs is failed, an absent one is missing.
func Verify(ctx context.Context, m Manifest, key []byte, store Store, now func() time.Time) (Report, error) {
	if now == nil {
		now = time.Now
	}
	start := now()
	r := Report{Failed: []string{}, Missing: []string{}}
	for _, it := range m.Items {
		v, err := store.Get(ctx, it.Path)
		switch {
		case errors.Is(err, ErrNotFound):
			r.Missing = append(r.Missing, it.Path)
			continue
		case err != nil:
			return Report{}, fmt.Errorf("migrate verify: %s: %w", it.Path, err)
		}
		got := MAC(key, v)
		clear(v)
		if hmac.Equal([]byte(got), []byte(it.MAC)) {
			r.OK++
		} else {
			r.Failed = append(r.Failed, it.Path)
		}
	}
	sort.Strings(r.Failed)
	sort.Strings(r.Missing)
	r.Duration = now().Sub(start).String()
	return r, nil
}
