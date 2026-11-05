//go:build darwin && cgo

package kek

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeIdentityRequiresUserPresence(t *testing.T) {
	if testing.Short() || os.Getenv("KEYLATCH_TEST_NATIVE_KEYCHAIN") != "1" {
		t.Skip("requires an interactive macOS session and KEYLATCH_TEST_NATIVE_KEYCHAIN=1")
	}
	suffix := make([]byte, 16)
	_, err := rand.Read(suffix)
	require.NoError(t, err)
	account := "vault-test-" + hex.EncodeToString(suffix)
	want := make([]byte, identitySize)
	_, err = rand.Read(want)
	require.NoError(t, err)
	defer zero(want)
	store := nativeKeychainIdentityStore{}
	require.NoError(t, store.Store(account, want))
	t.Cleanup(func() { require.NoError(t, store.Delete(account)) })
	unattended := nativeKeychainIdentityStore{noPrompt: true}
	got, err := unattended.Load(account)
	require.Error(t, err, "the protected identity must not be readable without presence")
	require.Empty(t, got)
	got, err = store.Load(account)
	require.NoError(t, err)
	defer zero(got)
	require.Equal(t, want, got)
}
