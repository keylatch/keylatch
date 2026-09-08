package connections

import (
	"context"
	"errors"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
)

// unavailableStore's existence read (Get) always errors, simulating a
// locked/unauthorized/transiently unavailable backend rather than a typed
// not-found. writes counts every Set call.
type unavailableStore struct{ writes int }

func (*unavailableStore) Get(context.Context, string) ([]byte, backend.Meta, error) {
	return nil, backend.Meta{}, errors.New("synthetic backend unavailable")
}

func (s *unavailableStore) Set(context.Context, string, []byte, backend.Meta) error {
	s.writes++
	return nil
}

func (*unavailableStore) List(context.Context, string) ([]backend.Entry, error) {
	return nil, nil
}

func (*unavailableStore) Delete(context.Context, string) error { return nil }

// KNOWN-FAILING (F29): Connect treats any non-nil error from the existence
// read as "does not exist" and proceeds to write, instead of requiring a
// typed not-found error.
func TestSecurityRegression_F29_ConnectStopsOnUnavailableExistenceCheck(t *testing.T) {
	s := &unavailableStore{}
	_, err := Connect(context.Background(), "openrouter", ConnectOptions{
		NonInteractive: true,
		Fields:         map[string][]byte{"api_key": []byte("synthetic-key")},
	}, s)
	if s.writes > 0 {
		t.Fatalf("unavailable existence check allowed %d writes; error=%v", s.writes, err)
	}
}
