//go:build windows

package kek

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

const dpapiEntropySize = 32

func platformIdentityStore() IdentityStore {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return nil
	}
	return &dpapiIdentityStore{dir: filepath.Join(base, "keylatch", "kek")}
}

// dpapiIdentityStore wraps the identity with DPAPI under the current user's
// logon credentials. Each file holds a random entropy blob followed by the
// DPAPI output, so the ciphertext alone is not enough to unwrap the key.
type dpapiIdentityStore struct {
	dir string
}

func (s *dpapiIdentityStore) Name() string { return "windows-dpapi" }

func (s *dpapiIdentityStore) path(account string) string {
	return filepath.Join(s.dir, account+".dpapi")
}

func (s *dpapiIdentityStore) Load(account string) ([]byte, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(s.path(account))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrIdentityNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(raw) <= dpapiEntropySize {
		return nil, errors.New("dpapi item is truncated")
	}
	plain, err := dpapiTransform(raw[dpapiEntropySize:], raw[:dpapiEntropySize], false)
	if err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer zero(plain)
	if len(plain) != identitySize {
		return nil, errors.New("dpapi item is not a 32-byte identity")
	}
	out := make([]byte, identitySize)
	copy(out, plain)
	return out, nil
}

func (s *dpapiIdentityStore) Store(account string, identity []byte) error {
	if err := validAccount(account); err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	entropy := make([]byte, dpapiEntropySize)
	if _, err := rand.Read(entropy); err != nil {
		return err
	}
	blob, err := dpapiTransform(identity, entropy, true)
	if err != nil {
		return fmt.Errorf("CryptProtectData: %w", err)
	}
	return writeFileAtomic(s.path(account), append(entropy, blob...))
}

func (s *dpapiIdentityStore) Delete(account string) error {
	if err := validAccount(account); err != nil {
		return err
	}
	if err := os.Remove(s.path(account)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrIdentityNotFound
		}
		return err
	}
	return nil
}

func dpapiTransform(in, entropy []byte, protect bool) ([]byte, error) {
	inBlob := windows.DataBlob{Size: uint32(len(in)), Data: &in[0]}
	entBlob := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&inBlob, nil, &entBlob, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&inBlob, nil, &entBlob, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) }()
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice(out.Data, out.Size))
	return res, nil
}
