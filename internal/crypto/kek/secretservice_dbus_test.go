//go:build linux || freebsd || openbsd || netbsd

package kek

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeService is an in-process Secret Service: it speaks the encrypted
// session, keeps items by attributes and can hold its collection locked
// behind a prompt.
type fakeService struct {
	key        []byte
	items      map[dbus.ObjectPath]fakeItem
	locked     bool
	prompted   bool
	dismiss    bool
	closed     int
	sawPlain   bool
	badSrvKey  bool
	nextItem   int
	collection dbus.ObjectPath
}

type fakeItem struct {
	attrs  map[string]string
	secret []byte
	locked bool
}

func newFakeService() *fakeService {
	return &fakeService{items: map[dbus.ObjectPath]fakeItem{}, collection: "/org/freedesktop/secrets/collection/login"}
}

func (f *fakeService) store() *secretServiceIdentityStore {
	return &secretServiceIdentityStore{connect: func() (secretBus, error) { return f, nil }}
}

func (f *fakeService) close() {}

func (f *fakeService) session() *secretSession { return &secretSession{key: f.key} }

func (f *fakeService) call(_ context.Context, path dbus.ObjectPath, method string, args ...any) ([]any, error) {
	switch method {
	case serviceIface + ".OpenSession":
		if args[0] != dhAlgorithm {
			return nil, errors.New("unsupported algorithm")
		}
		clientPub := args[1].(dbus.Variant).Value().([]byte)
		priv, _ := rand.Int(rand.Reader, new(big.Int).Sub(oakleyGroup2, big.NewInt(3)))
		priv.Add(priv, big.NewInt(2))
		var err error
		if f.key, err = deriveSessionKey(priv, clientPub); err != nil {
			return nil, err
		}
		pub := new(big.Int).Exp(big.NewInt(2), priv, oakleyGroup2).FillBytes(make([]byte, dhPrimeBytes))
		if f.badSrvKey {
			pub = []byte{1}
		}
		return []any{dbus.MakeVariant(pub), dbus.ObjectPath("/session/1")}, nil
	case sessionIface + ".Close":
		f.closed++
		return nil, nil
	case serviceIface + ".ReadAlias":
		return []any{f.collection}, nil
	case serviceIface + ".Unlock":
		paths := args[0].([]dbus.ObjectPath)
		if f.locked {
			return []any{[]dbus.ObjectPath{}, dbus.ObjectPath("/prompt/1")}, nil
		}
		return []any{paths, noPrompt}, nil
	case serviceIface + ".SearchItems":
		want := args[0].(map[string]string)
		unlocked, locked := []dbus.ObjectPath{}, []dbus.ObjectPath{}
		for p, it := range f.items {
			if it.attrs["account"] != want["account"] || it.attrs["application"] != want["application"] || it.attrs["purpose"] != want["purpose"] {
				continue
			}
			if it.locked && f.locked {
				locked = append(locked, p)
			} else {
				unlocked = append(unlocked, p)
			}
		}
		return []any{unlocked, locked}, nil
	case collectionIface + ".CreateItem":
		props := args[0].(map[string]dbus.Variant)
		sv := args[1].(secretValue)
		plain, err := f.session().open(sv)
		if err != nil {
			return nil, err
		}
		if bytes.Contains(sv.Value, plain) {
			f.sawPlain = true
		}
		attrs := props[itemIface+".Attributes"].Value().(map[string]string)
		for p, it := range f.items {
			if args[2] == true && it.attrs["account"] == attrs["account"] {
				delete(f.items, p)
			}
		}
		f.nextItem++
		p := dbus.ObjectPath("/item/" + string(rune('a'+f.nextItem)))
		f.items[p] = fakeItem{attrs: attrs, secret: plain, locked: f.locked}
		return []any{p, noPrompt}, nil
	case itemIface + ".GetSecret":
		it := f.items[path]
		sv, err := f.session().seal(it.secret)
		return []any{sv}, err
	case itemIface + ".Delete":
		delete(f.items, path)
		return []any{noPrompt}, nil
	}
	return nil, errors.New("unexpected call " + method)
}

func (f *fakeService) prompt(context.Context, dbus.ObjectPath) (bool, error) {
	f.prompted = true
	if f.dismiss {
		return true, nil
	}
	f.locked = false
	return false, nil
}

func identity(b byte) []byte { return bytes.Repeat([]byte{b}, identitySize) }

func TestSecretService_RoundTripUsesTheEncryptedSession(t *testing.T) {
	f := newFakeService()
	s := f.store()

	require.NoError(t, s.Store("vault-01", identity(0xab)))
	assert.False(t, f.sawPlain, "the secret crossed the bus in the clear")
	got, err := s.Load("vault-01")
	require.NoError(t, err)
	assert.Equal(t, identity(0xab), got)
	assert.Equal(t, 2, f.closed, "every operation closes its session")

	require.NoError(t, s.Store("vault-01", identity(0xcd)))
	got, err = s.Load("vault-01")
	require.NoError(t, err)
	assert.Equal(t, identity(0xcd), got)

	require.NoError(t, s.Delete("vault-01"))
	_, err = s.Load("vault-01")
	require.ErrorIs(t, err, ErrIdentityNotFound)
	require.ErrorIs(t, s.Delete("vault-01"), ErrIdentityNotFound)
}

func TestSecretService_ItemAttributesMatchEarlierInstalls(t *testing.T) {
	f := newFakeService()
	require.NoError(t, f.store().Store("vault-01", identity(1)))
	for _, it := range f.items {
		assert.Equal(t, map[string]string{"application": "keylatch", "purpose": "kek", "account": "vault-01"}, it.attrs)
		assert.Equal(t, hexOf(identity(1)), string(it.secret), "the secret is the hex text earlier versions stored")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range b {
		sb.WriteByte(digits[c>>4])
		sb.WriteByte(digits[c&15])
	}
	return sb.String()
}

func TestSecretService_LockedCollectionAsksTheUser(t *testing.T) {
	f := newFakeService()
	s := f.store()
	require.NoError(t, s.Store("vault-01", identity(7)))

	f.locked = true
	for k, it := range f.items {
		it.locked = true
		f.items[k] = it
	}
	got, err := s.Load("vault-01")
	require.NoError(t, err)
	assert.Equal(t, identity(7), got)
	assert.True(t, f.prompted)

	f.locked, f.prompted, f.dismiss = true, false, true
	_, err = s.Load("vault-01")
	require.ErrorContains(t, err, "dismissed")
	require.ErrorContains(t, s.Store("vault-02", identity(8)), "dismissed")
}

func TestSecretService_RefusesBadServerKeyAndBadItems(t *testing.T) {
	f := newFakeService()
	f.badSrvKey = true
	require.ErrorContains(t, f.store().Store("vault-01", identity(1)), "out of range")

	f = newFakeService()
	require.NoError(t, f.store().Store("vault-01", identity(1)))
	for k, it := range f.items {
		it.secret = []byte("not-hex")
		f.items[k] = it
	}
	_, err := f.store().Load("vault-01")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrIdentityNotFound)
}

func TestSecretService_RejectsUnsafeAccounts(t *testing.T) {
	f := newFakeService()
	s := f.store()
	require.Error(t, s.Store("a -w leak\nadd", identity(1)))
	_, err := s.Load("A B")
	require.Error(t, err)
	require.Error(t, s.Delete(""))
	assert.Zero(t, f.nextItem)
}

type failingService struct {
	*fakeService
	method string
}

func (f failingService) call(ctx context.Context, p dbus.ObjectPath, method string, args ...any) ([]any, error) {
	if method == f.method {
		return nil, errors.New("bus refused " + method)
	}
	return f.fakeService.call(ctx, p, method, args...)
}

func TestSecretService_EveryStepReportsItsFailure(t *testing.T) {
	for _, tc := range []struct {
		method string
		op     string
	}{
		{serviceIface + ".OpenSession", "load"},
		{serviceIface + ".ReadAlias", "store"},
		{serviceIface + ".Unlock", "store"},
		{serviceIface + ".SearchItems", "load"},
		{collectionIface + ".CreateItem", "store"},
		{itemIface + ".GetSecret", "load"},
		{itemIface + ".Delete", "delete"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			base := newFakeService()
			require.NoError(t, base.store().Store("vault-01", identity(1)))
			s := &secretServiceIdentityStore{connect: func() (secretBus, error) { return failingService{base, tc.method}, nil }}
			var err error
			switch tc.op {
			case "store":
				err = s.Store("vault-02", identity(2))
			case "load":
				_, err = s.Load("vault-01")
			case "delete":
				err = s.Delete("vault-01")
			}
			require.ErrorContains(t, err, "bus refused "+tc.method)
		})
	}
}

func TestSecretService_ConnectionFailureIsReported(t *testing.T) {
	s := &secretServiceIdentityStore{connect: func() (secretBus, error) { return nil, errors.New("no bus") }}
	_, err := s.Load("vault-01")
	require.ErrorContains(t, err, "no bus")
}

type closingService struct {
	*fakeService
	key        []byte
	bounded    bool
	keyCleared bool
	disconnect bool
}

func (f *closingService) call(ctx context.Context, p dbus.ObjectPath, method string, args ...any) ([]any, error) {
	if method == sessionIface+".Close" {
		_, f.bounded = ctx.Deadline()
		f.keyCleared = bytes.Equal(f.key, make([]byte, len(f.key)))
		return nil, errors.New("service unavailable during close")
	}
	return f.fakeService.call(ctx, p, method, args...)
}

func (f *closingService) close() { f.disconnect = true }

func TestSecretService_CloseClearsKeyBeforeBoundedCleanup(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	bus := &closingService{fakeService: newFakeService(), key: key}
	ss := &secretSession{bus: bus, path: "/session/1", key: key}
	ss.close()
	assert.True(t, bus.bounded, "session cleanup must have a deadline")
	assert.True(t, bus.keyCleared, "erase the key before contacting the service")
	assert.True(t, bus.disconnect, "disconnect even when session cleanup fails")
}

func TestSecretService_TransportPrimeIsASafePrime(t *testing.T) {
	require.Equal(t, dhPrimeBytes*8, oakleyGroup2.BitLen())
	assert.True(t, oakleyGroup2.ProbablyPrime(20))
	q := new(big.Int).Rsh(new(big.Int).Sub(oakleyGroup2, big.NewInt(1)), 1)
	assert.True(t, q.ProbablyPrime(20))
}

func TestSecretService_SealRejectsTruncatedSecrets(t *testing.T) {
	ss := &secretSession{key: bytes.Repeat([]byte{1}, 16)}
	sv, err := ss.seal([]byte("abc"))
	require.NoError(t, err)
	plain, err := ss.open(sv)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(plain))

	sv.Value = sv.Value[:len(sv.Value)-1]
	_, err = ss.open(sv)
	require.Error(t, err)
	sv.Value = nil
	_, err = ss.open(sv)
	require.Error(t, err)
}

type malformedService struct {
	*fakeService
	method string
	body   []any
}

func (f malformedService) call(ctx context.Context, p dbus.ObjectPath, method string, args ...any) ([]any, error) {
	if method == f.method {
		return f.body, nil
	}
	return f.fakeService.call(ctx, p, method, args...)
}

func TestSecretService_RejectsMalformedReplies(t *testing.T) {
	for _, method := range []string{
		serviceIface + ".OpenSession", serviceIface + ".ReadAlias", serviceIface + ".Unlock",
		serviceIface + ".SearchItems", collectionIface + ".CreateItem", itemIface + ".GetSecret", itemIface + ".Delete",
	} {
		t.Run(method, func(t *testing.T) {
			base := newFakeService()
			require.NoError(t, base.store().Store("vault-01", identity(1)))
			s := &secretServiceIdentityStore{connect: func() (secretBus, error) {
				return malformedService{base, method, []any{42}}, nil
			}}
			var err error
			switch method {
			case serviceIface + ".ReadAlias", serviceIface + ".Unlock", collectionIface + ".CreateItem":
				err = s.Store("vault-02", identity(2))
			case itemIface + ".Delete":
				err = s.Delete("vault-01")
			default:
				_, err = s.Load("vault-01")
			}
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrIdentityNotFound)
		})
	}
	base := newFakeService()
	s := &secretServiceIdentityStore{connect: func() (secretBus, error) {
		return malformedService{base, serviceIface + ".OpenSession", []any{dbus.MakeVariant("not a public key"), dbus.ObjectPath("/session/1")}}, nil
	}}
	_, err := s.Load("vault-01")
	require.ErrorContains(t, err, "no public key")
}

func TestSecretService_RejectsInvalidKeyAndPadding(t *testing.T) {
	ss := &secretSession{key: bytes.Repeat([]byte{1}, 16)}
	sv, err := ss.seal([]byte("abc"))
	require.NoError(t, err)
	sv.Parameters[len(sv.Parameters)-1] ^= 1
	_, err = ss.open(sv)
	require.ErrorContains(t, err, "malformed")
	ss.key = []byte{1}
	_, err = ss.open(sv)
	require.Error(t, err)
	_, err = ss.seal([]byte("abc"))
	require.Error(t, err)
}

func TestSessionBusConfigured(t *testing.T) {
	dir := t.TempDir()
	lookup := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	assert.True(t, sessionBusConfigured(lookup(map[string]string{"DBUS_SESSION_BUS_ADDRESS": "unix:path=/x"})))
	assert.False(t, sessionBusConfigured(lookup(map[string]string{"XDG_RUNTIME_DIR": dir})))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bus"), nil, 0o600))
	assert.True(t, sessionBusConfigured(lookup(map[string]string{"XDG_RUNTIME_DIR": dir})))
	assert.False(t, sessionBusConfigured(lookup(nil)))
}
