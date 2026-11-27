//go:build !fips

package kek

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type unavailableIdentityStore struct {
	IdentityStore
	loadErr   error
	deleteErr error
}

func (s unavailableIdentityStore) Load(account string) ([]byte, error) {
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return s.IdentityStore.Load(account)
}

func (s unavailableIdentityStore) Delete(account string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.IdentityStore.Delete(account)
}

func TestProtectedIdentityMigratesOnlyAfterPresenceAndVerification(t *testing.T) {
	native, legacy := newFakeStore(), newFakeStore()
	want := bytes.Repeat([]byte{7}, identitySize)
	require.NoError(t, legacy.Store("vault-aa", want))
	confirmed := false
	s := &protectedIdentityStore{native: native, legacy: legacy, confirm: func(account string) error {
		require.Equal(t, "vault-aa", account)
		require.Empty(t, native.items)
		confirmed = true
		return nil
	}}
	got, err := s.Load("vault-aa")
	require.NoError(t, err)
	require.True(t, confirmed)
	require.Equal(t, want, got)
	require.Equal(t, want, native.items["vault-aa"])
	require.Empty(t, legacy.items)
	confirmed = false
	got, err = s.Load("vault-aa")
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.False(t, confirmed)
}

func TestProtectedIdentityKeepsLegacyOnMigrationFailure(t *testing.T) {
	for _, failure := range []string{"presence", "store", "verify", "delete"} {
		t.Run(failure, func(t *testing.T) {
			native, legacy := newFakeStore(), newFakeStore()
			want := bytes.Repeat([]byte{7}, identitySize)
			require.NoError(t, legacy.Store("vault-aa", want))
			s := &protectedIdentityStore{native: native, legacy: legacy, confirm: func(string) error { return nil }}
			switch failure {
			case "presence":
				s.confirm = func(string) error { return errors.New("declined") }
			case "store":
				native.storeErr = errors.New("store failed")
			case "verify":
				native.corrupt = true
			case "delete":
				s.legacy = unavailableIdentityStore{IdentityStore: legacy, deleteErr: errors.New("delete failed")}
			}
			for range 2 {
				got, err := s.Load("vault-aa")
				require.Error(t, err)
				require.Nil(t, got)
				require.Equal(t, want, legacy.items["vault-aa"])
			}
		})
	}
}

func TestProtectedIdentityNeverFallsBackOnNativeFailure(t *testing.T) {
	native, legacy := newFakeStore(), newFakeStore()
	refused := errors.New("native access refused")
	s := &protectedIdentityStore{
		native: unavailableIdentityStore{IdentityStore: native, loadErr: refused}, legacy: legacy,
		confirm: func(string) error { t.Fatal("must not fall back after native refusal"); return nil },
	}
	_, err := s.Load("vault-aa")
	require.ErrorIs(t, err, refused)
}

func TestProtectedIdentityWritesOnlyNativeAndDeletesBothStores(t *testing.T) {
	native, legacy := newFakeStore(), newFakeStore()
	s := &protectedIdentityStore{native: native, legacy: legacy}
	require.Equal(t, "macos-keychain", s.Name())
	want := bytes.Repeat([]byte{7}, identitySize)
	require.NoError(t, s.Store("vault-aa", want))
	require.Empty(t, legacy.items)
	require.NoError(t, legacy.Store("vault-aa", want))
	require.NoError(t, s.Delete("vault-aa"))
	require.Empty(t, native.items)
	require.Empty(t, legacy.items)
	require.ErrorIs(t, s.Delete("vault-aa"), ErrIdentityNotFound)
	require.NoError(t, s.Store("vault-aa", want))
	require.NoError(t, s.Delete("vault-aa"))
	require.Error(t, s.Store("invalid account", want))
	_, err := s.Load("invalid account")
	require.Error(t, err)
	require.Error(t, s.Delete("invalid account"))
}
