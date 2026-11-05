package kek

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeychainStore_DeleteAndLoadErrors(t *testing.T) {
	var calls []runnerCall
	s := &keychainIdentityStore{bin: "/usr/bin/security", run: recordingRunner(&calls, nil, nil, nil)}
	require.NoError(t, s.Delete("vault-aa"))
	assert.Equal(t, []string{"delete-generic-password", "-s", "keylatch-vault-kek", "-a", "vault-aa"}, calls[0].args)

	s.run = recordingRunner(&calls, nil, nil, exitErr(keychainItemNotFoundExit))
	require.ErrorIs(t, s.Delete("vault-aa"), ErrIdentityNotFound)

	s.run = recordingRunner(&calls, nil, []byte("denied"), exitErr(1))
	err := s.Delete("vault-aa")
	require.ErrorContains(t, err, "denied")
	assert.NotErrorIs(t, err, ErrIdentityNotFound)
	_, err = s.Load("vault-aa")
	require.ErrorContains(t, err, "denied")

	s.run = recordingRunner(&calls, nil, nil, errors.New("plain failure"))
	require.ErrorContains(t, s.Delete("vault-aa"), "plain failure")
	assert.Equal(t, -1, exitCode(errors.New("plain failure")))
}
