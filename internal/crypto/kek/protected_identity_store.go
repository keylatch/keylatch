package kek

import (
	"crypto/subtle"
	"errors"
	"fmt"
)

// protectedIdentityStore migrates legacy items only after presence and verified native storage.
type protectedIdentityStore struct {
	native  IdentityStore
	legacy  IdentityStore
	confirm func(string) error
}

func (*protectedIdentityStore) Name() string { return "macos-keychain" }

func (s *protectedIdentityStore) Load(account string) ([]byte, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	identity, err := s.native.Load(account)
	if err == nil {
		legacy, legacyErr := s.legacy.Load(account)
		defer zero(legacy)
		if legacyErr != nil && !errors.Is(legacyErr, ErrIdentityNotFound) {
			zero(identity)
			return nil, fmt.Errorf("check legacy keychain identity: %w", legacyErr)
		}
		if legacyErr == nil && subtle.ConstantTimeCompare(identity, legacy) != 1 {
			zero(identity)
			return nil, errors.New("protected keychain identity differs; legacy item retained")
		}
		if err := s.removeLegacy(account); err != nil {
			zero(identity)
			return nil, err
		}
		return identity, nil
	}
	if !errors.Is(err, ErrIdentityNotFound) {
		return nil, err
	}
	if err := s.confirm(account); err != nil {
		return nil, fmt.Errorf("authorize keychain protection upgrade: %w", err)
	}
	identity, err = s.legacy.Load(account)
	if err != nil {
		return nil, err
	}
	defer zero(identity)
	if err := s.native.Store(account, identity); err != nil {
		return nil, fmt.Errorf("protect legacy keychain identity: %w", err)
	}
	held, err := s.native.Load(account)
	if err != nil {
		return nil, fmt.Errorf("verify protected keychain identity: %w", err)
	}
	if subtle.ConstantTimeCompare(held, identity) != 1 {
		zero(held)
		return nil, errors.New("protected keychain identity differs; legacy item retained")
	}
	if err := s.removeLegacy(account); err != nil {
		zero(held)
		return nil, err
	}
	return held, nil
}

func (s *protectedIdentityStore) removeLegacy(account string) error {
	err := s.legacy.Delete(account)
	if err != nil && !errors.Is(err, ErrIdentityNotFound) {
		return fmt.Errorf("remove legacy keychain identity: %w", err)
	}
	return nil
}

func (s *protectedIdentityStore) Store(account string, identity []byte) error {
	if err := validAccount(account); err != nil {
		return err
	}
	return s.native.Store(account, identity)
}

func (s *protectedIdentityStore) Delete(account string) error {
	if err := validAccount(account); err != nil {
		return err
	}
	nativeErr := s.native.Delete(account)
	if nativeErr != nil && !errors.Is(nativeErr, ErrIdentityNotFound) {
		return nativeErr
	}
	legacyErr := s.legacy.Delete(account)
	if errors.Is(legacyErr, ErrIdentityNotFound) && nativeErr == nil {
		return nil
	}
	return legacyErr
}
