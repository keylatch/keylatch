package kek

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeychainStore_DeleteAndFailures(t *testing.T) {
	var calls []runnerCall
	s := &keychainIdentityStore{bin: "/usr/bin/security", run: recordingRunner(&calls, nil, nil, nil)}
	require.NoError(t, s.Delete("vault-aa"))
	assert.Equal(t, []string{"delete-generic-password", "-s", "keylatch-vault-kek", "-a", "vault-aa"}, calls[0].args)

	s.run = recordingRunner(&calls, nil, nil, exitErr(keychainItemNotFoundExit))
	assert.ErrorIs(t, s.Delete("vault-aa"), ErrIdentityNotFound)

	s.run = recordingRunner(&calls, nil, []byte("denied"), exitErr(1))
	err := s.Delete("vault-aa")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrIdentityNotFound)
	assert.Contains(t, err.Error(), "denied")
	_, err = s.Load("vault-aa")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrIdentityNotFound)
	assert.Error(t, s.Store("vault-aa", make([]byte, identitySize)))
}

func TestSecretServiceStore_DeleteAndFailures(t *testing.T) {
	var calls []runnerCall
	s := &secretServiceIdentityStore{bin: "secret-tool", run: recordingRunner(&calls, nil, nil, nil)}
	require.NoError(t, s.Delete("vault-01"))
	assert.Equal(t, []string{"clear", "application", "keylatch", "purpose", "kek", "account", "vault-01"}, calls[0].args)

	s.run = recordingRunner(&calls, nil, []byte("no session"), exitErr(1))
	err := s.Delete("vault-01")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no session")
	assert.Error(t, s.Store("vault-01", make([]byte, identitySize)))
}

func TestExitCodeAndCommandError(t *testing.T) {
	assert.Equal(t, 7, exitCode(exitErr(7)))
	assert.Equal(t, -1, exitCode(errors.New("plain")))

	base := errors.New("failed")
	err := commandError("tool", base, []byte(" detail \n"))
	assert.ErrorIs(t, err, base)
	assert.Contains(t, err.Error(), "detail")
	assert.Equal(t, "tool: failed", commandError("tool", base, nil).Error())
}
