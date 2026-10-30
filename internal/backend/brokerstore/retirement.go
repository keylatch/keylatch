package brokerstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/keylatch/keylatch/internal/backend"
)

// ErrRetired means the version's value has been replaced with an authenticated tombstone.
var ErrRetired = errors.New("brokerstore: version is retired")

// ErrVersionChanged refuses work approved for a different stored record.
var ErrVersionChanged = errors.New("brokerstore: source version changed")

// Retirement identifies both versions without retaining their plaintext values.
type Retirement struct {
	Path           string
	CurrentVersion int
	CurrentID      string
	PreviousID     string
}

// SnapshotForRetirement atomically binds the returned values to retirement identities.
// Callers wipe both values; an empty reference means no previous version exists.
func (s *Store) SnapshotForRetirement(_ context.Context, p string) ([]byte, []byte, backend.Meta, Retirement, error) {
	if err := validPath(p); err != nil {
		return nil, nil, backend.Meta{}, Retirement{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.read(p)
	if err != nil {
		return nil, nil, backend.Meta{}, Retirement{}, err
	}
	value, meta, err := s.decrypt(current)
	if err != nil {
		return nil, nil, backend.Meta{}, Retirement{}, err
	}
	if current.Version < 2 {
		return value, nil, meta, Retirement{}, nil
	}
	previous, err := s.retirementRecord(p, current.Version-1)
	var old []byte
	if err == nil {
		old, _, err = s.decrypt(previous)
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrRetired) {
		return value, nil, meta, Retirement{}, nil
	}
	if err != nil {
		clear(value)
		return nil, nil, backend.Meta{}, Retirement{}, err
	}
	ref := Retirement{Path: p, CurrentVersion: current.Version, CurrentID: s.recordID(current), PreviousID: s.recordID(previous)}
	return value, old, meta, ref, nil
}

// Retire replaces only the identified previous version; retries are idempotent.
func (s *Store) Retire(_ context.Context, ref Retirement) error {
	if err := validPath(ref.Path); err != nil {
		return err
	}
	if ref.CurrentVersion < 2 || !validRecordID(ref.CurrentID) || !validRecordID(ref.PreviousID) {
		return ErrVersionChanged
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, err := s.read(ref.Path)
	if err != nil {
		return err
	}
	value, _, err := s.decrypt(current)
	clear(value)
	if err != nil {
		return err
	}
	if current.Version != ref.CurrentVersion || s.recordID(current) != ref.CurrentID {
		return ErrVersionChanged
	}
	previous, err := s.retirementRecord(ref.Path, ref.CurrentVersion-1)
	if err != nil {
		return err
	}
	value, err = s.decryptRecord(previous)
	defer clear(value)
	if err != nil {
		return err
	}
	if previous.Retired {
		if string(value) == ref.PreviousID {
			return nil
		}
		return ErrVersionChanged
	}
	if s.recordID(previous) != ref.PreviousID {
		return ErrVersionChanged
	}
	previous.Retired = true
	previous.Updated = s.now().UTC()
	previous, err = s.encrypt(previous, []byte(ref.PreviousID))
	if err != nil {
		return err
	}
	return s.writeTo(s.versionFile(ref.Path, previous.Version), previous)
}

func (s *Store) retirementRecord(p string, version int) (record, error) {
	var rec record
	if err := readJSON(s.versionFile(p, version), &rec); err != nil {
		return rec, err
	}
	if rec.V != recordFormat || rec.Path != p || rec.Version != version {
		return rec, ErrAAD
	}
	return rec, nil
}

func validRecordID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return err == nil && len(decoded) == sha256.Size
}

// recordID stays stable across master-key rewraps but changes on replacement.
func (s *Store) recordID(rec record) string {
	h := sha256.New()
	_, _ = h.Write(s.recordAAD(rec))
	_, _ = h.Write(rec.Nonce)
	_, _ = h.Write(rec.CT)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Store) recordAAD(rec record) []byte {
	aad := s.aad(rec.Path, rec.Version)
	if rec.Retired {
		aad = append(aad, "\x00retired/v1"...)
	}
	return aad
}

func (s *Store) encrypt(rec record, value []byte) (record, error) {
	dek := make([]byte, dekLen)
	defer clear(dek)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return record{}, fmt.Errorf("brokerstore: %w", err)
	}
	aad := s.recordAAD(rec)
	nonce, ct, err := seal(dek, value, aad)
	if err != nil {
		return record{}, err
	}
	kid, kek := s.keys.StoreKEK(s.partition)
	defer clear(kek)
	dekNonce, wrapped, err := seal(kek, dek, append(aad, kid...))
	if err != nil {
		return record{}, err
	}
	rec.KID, rec.DEKNonce, rec.WrappedDEK = kid, dekNonce, wrapped
	rec.Nonce, rec.CT = nonce, ct
	return rec, nil
}
