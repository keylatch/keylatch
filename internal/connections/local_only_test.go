package connections

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/localonly"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func connectLocal(t *testing.T, store *mockStore, class localonly.Class, modes map[string]localonly.Mode, fields map[string][]byte) (*Connection, error) {
	t.Helper()
	return Connect(context.Background(), "openrouter", ConnectOptions{
		NonInteractive: true,
		Class:          class,
		LocalOnly:      modes,
		Fields:         fields,
	}, store)
}

func TestConnectEphemeralStoresNoValue(t *testing.T) {
	store := newMockStore()
	conn, err := connectLocal(t, store, localonly.ClassDev, map[string]localonly.Mode{"api_key": localonly.Ephemeral}, nil)
	require.NoError(t, err)
	assert.Equal(t, localonly.Ephemeral, conn.LocalOnly["api_key"])
	assert.Equal(t, localonly.ClassDev, conn.Class)
	_, ok := store.storedValue(secretFieldPath("default", "ai", "openrouter", "api_key"))
	assert.False(t, ok, "ephemeral field must not be stored")

	loaded, err := Load(context.Background(), "default", "openrouter", store)
	require.NoError(t, err)
	assert.Equal(t, localonly.Ephemeral, loaded.LocalOnly["api_key"])
}

func TestConnectEphemeralRejectedOutsideDevTest(t *testing.T) {
	modes := map[string]localonly.Mode{"api_key": localonly.Ephemeral}
	for _, class := range []localonly.Class{localonly.ClassProd, ""} {
		_, err := connectLocal(t, newMockStore(), class, modes, nil)
		assert.ErrorIs(t, err, localonly.ErrEphemeralClass, "class %q", class)
	}
}

func TestConnectLocalOnlyValidation(t *testing.T) {
	_, err := connectLocal(t, newMockStore(), localonly.ClassDev, map[string]localonly.Mode{"nope": localonly.Ephemeral}, nil)
	assert.Error(t, err)
	_, err = connectLocal(t, newMockStore(), localonly.ClassDev, map[string]localonly.Mode{"api_key": "bogus"}, nil)
	assert.ErrorIs(t, err, localonly.ErrInvalidMode)
	_, err = connectLocal(t, newMockStore(), "staging", nil, map[string][]byte{"api_key": []byte("x")})
	assert.ErrorIs(t, err, localonly.ErrInvalidClass)
	_, err = connectLocal(t, newMockStore(), localonly.ClassDev, map[string]localonly.Mode{"api_key": localonly.Ephemeral}, map[string][]byte{"api_key": []byte("x")})
	assert.Error(t, err)
}

func TestConnectAcceptsUnimplementedModesInModel(t *testing.T) {
	conn, err := connectLocal(t, newMockStore(), localonly.ClassProd, map[string]localonly.Mode{"api_key": localonly.Operation}, map[string][]byte{"api_key": []byte("v")})
	require.NoError(t, err)
	assert.Equal(t, localonly.Operation, conn.LocalOnly["api_key"])
}

func TestSetLocalOnlyHumanOnlyWhenWeakening(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	_, err := connectLocal(t, store, localonly.ClassDev, map[string]localonly.Mode{"api_key": localonly.Ephemeral}, nil)
	require.NoError(t, err)

	err = SetLocalOnly(ctx, "default", "openrouter", "api_key", localonly.Contained, false, store)
	assert.ErrorIs(t, err, ErrHumanOnly)
	err = SetLocalOnly(ctx, "default", "openrouter", "api_key", "", false, store)
	assert.ErrorIs(t, err, ErrHumanOnly)

	require.NoError(t, SetLocalOnly(ctx, "default", "openrouter", "api_key", localonly.Contained, true, store))
	loaded, _ := Load(ctx, "default", "openrouter", store)
	assert.Equal(t, localonly.Contained, loaded.LocalOnly["api_key"])

	require.NoError(t, SetLocalOnly(ctx, "default", "openrouter", "api_key", localonly.Operation, false, store), "strengthening is open to any caller")
}

func TestSetLocalOnlyRejectsEphemeralOnProd(t *testing.T) {
	ctx := context.Background()
	store := newMockStore()
	_, err := connectLocal(t, store, localonly.ClassProd, nil, map[string][]byte{"api_key": []byte("v")})
	require.NoError(t, err)
	err = SetLocalOnly(ctx, "default", "openrouter", "api_key", localonly.Ephemeral, true, store)
	assert.ErrorIs(t, err, localonly.ErrEphemeralClass)
}
