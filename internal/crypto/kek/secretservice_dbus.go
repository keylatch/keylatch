//go:build linux || freebsd || openbsd || netbsd

package kek

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/godbus/dbus/v5"
)

const (
	secretsName      = "org.freedesktop.secrets"
	secretsPath      = dbus.ObjectPath("/org/freedesktop/secrets")
	serviceIface     = "org.freedesktop.Secret.Service"
	itemIface        = "org.freedesktop.Secret.Item"
	promptIface      = "org.freedesktop.Secret.Prompt"
	sessionIface     = "org.freedesktop.Secret.Session"
	collectionIface  = "org.freedesktop.Secret.Collection"
	dhAlgorithm      = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
	noPrompt         = dbus.ObjectPath("/")
	dhPrimeBytes     = 128
	secretContentTyp = "text/plain"
)

// oakleyGroup2 is the 1024-bit MODP group of RFC 2409, the one the Secret
// Service names in its encrypted transport.
var oakleyGroup2, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"+
		"020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"+
		"4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)

// secretBus is the part of a D-Bus connection the store uses, so tests can
// stand in a service without a bus daemon.
type secretBus interface {
	call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) ([]any, error)
	// prompt shows the service's own prompt and reports whether the user
	// dismissed it.
	prompt(ctx context.Context, path dbus.ObjectPath) (dismissed bool, err error)
	close()
}

type secretValue struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// secretServiceIdentityStore keeps the identity in the freedesktop Secret
// Service (GNOME Keyring, KWallet) over D-Bus. Secrets cross the bus only
// inside the service's encrypted session, never in the clear, and no helper
// process or argument list ever carries them.
type secretServiceIdentityStore struct {
	connect func(context.Context) (secretBus, error)
}

func newSecretServiceIdentityStore() IdentityStore {
	return &secretServiceIdentityStore{connect: connectSessionBus}
}

func (*secretServiceIdentityStore) Name() string { return "secret-service" }

func attrsFor(account string) map[string]string {
	return map[string]string{"application": "keylatch", "purpose": "kek", "account": account}
}

type secretSession struct {
	bus  secretBus
	path dbus.ObjectPath
	key  []byte
}

func (s *secretServiceIdentityStore) open(ctx context.Context) (*secretSession, error) {
	bus, err := s.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("secret service: %w", err)
	}
	priv, err := rand.Int(rand.Reader, new(big.Int).Sub(oakleyGroup2, big.NewInt(3)))
	if err != nil {
		bus.close()
		return nil, err
	}
	priv.Add(priv, big.NewInt(2))
	pub := new(big.Int).Exp(big.NewInt(2), priv, oakleyGroup2).FillBytes(make([]byte, dhPrimeBytes))

	body, err := bus.call(ctx, secretsPath, serviceIface+".OpenSession", dhAlgorithm, dbus.MakeVariant(pub))
	if err != nil {
		bus.close()
		return nil, fmt.Errorf("secret service: open session: %w", err)
	}
	var server dbus.Variant
	var path dbus.ObjectPath
	if err := dbus.Store(body, &server, &path); err != nil {
		bus.close()
		return nil, fmt.Errorf("secret service: open session: %w", err)
	}
	if !path.IsValid() || path == noPrompt {
		bus.close()
		return nil, errors.New("secret service: invalid session path")
	}
	serverPub, ok := server.Value().([]byte)
	if !ok {
		bus.close()
		return nil, errors.New("secret service: the session reply carries no public key")
	}
	key, err := deriveSessionKey(priv, serverPub)
	if err != nil {
		bus.close()
		return nil, err
	}
	return &secretSession{bus: bus, path: path, key: key}, nil
}

func (ss *secretSession) close() {
	clear(ss.key)
	defer ss.bus.close()
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	_, _ = ss.bus.call(ctx, ss.path, sessionIface+".Close")
}

func deriveSessionKey(priv *big.Int, serverPub []byte) ([]byte, error) {
	b := new(big.Int).SetBytes(serverPub)
	if b.Cmp(big.NewInt(1)) <= 0 || b.Cmp(new(big.Int).Sub(oakleyGroup2, big.NewInt(1))) >= 0 {
		return nil, errors.New("secret service: the session public key is out of range")
	}
	shared := new(big.Int).Exp(b, priv, oakleyGroup2).FillBytes(make([]byte, dhPrimeBytes))
	defer clear(shared)
	return hkdf.Key(sha256.New, shared, nil, "", 16)
}

func (ss *secretSession) seal(plain []byte) (secretValue, error) {
	block, err := aes.NewCipher(ss.key)
	if err != nil {
		return secretValue{}, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return secretValue{}, err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append(make([]byte, 0, len(plain)+pad), plain...), repeatByte(byte(pad), pad)...)
	defer clear(padded)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded) //nolint:staticcheck // the Secret Service transport is defined as AES-128-CBC
	return secretValue{Session: ss.path, Parameters: iv, Value: out, ContentType: secretContentTyp}, nil
}

func (ss *secretSession) open(v secretValue) ([]byte, error) {
	if len(v.Parameters) != aes.BlockSize || len(v.Value) == 0 || len(v.Value)%aes.BlockSize != 0 {
		return nil, errors.New("secret service: malformed encrypted secret")
	}
	block, err := aes.NewCipher(ss.key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(v.Value))
	cipher.NewCBCDecrypter(block, v.Parameters).CryptBlocks(out, v.Value) //nolint:staticcheck // the Secret Service transport is defined as AES-128-CBC
	pad := int(out[len(out)-1])
	if pad == 0 || pad > aes.BlockSize || pad > len(out) ||
		subtle.ConstantTimeCompare(out[len(out)-pad:], repeatByte(byte(pad), pad)) != 1 {
		clear(out)
		return nil, errors.New("secret service: malformed encrypted secret")
	}
	return out[:len(out)-pad], nil
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// resolve waits out the user's answer to a service prompt.
func resolve(ctx context.Context, bus secretBus, prompt dbus.ObjectPath) error {
	if !prompt.IsValid() {
		return errors.New("secret service: invalid prompt path")
	}
	if prompt == noPrompt {
		return nil
	}
	dismissed, err := bus.prompt(ctx, prompt)
	if err != nil {
		return err
	}
	if dismissed {
		return errors.New("secret service: the prompt was dismissed")
	}
	return nil
}

func (ss *secretSession) unlock(ctx context.Context, paths ...dbus.ObjectPath) ([]dbus.ObjectPath, error) {
	body, err := ss.bus.call(ctx, secretsPath, serviceIface+".Unlock", paths)
	if err != nil {
		return nil, fmt.Errorf("secret service: unlock: %w", err)
	}
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := dbus.Store(body, &unlocked, &prompt); err != nil {
		return nil, fmt.Errorf("secret service: unlock: %w", err)
	}
	if prompt == noPrompt {
		return unlocked, nil
	}
	// The collection unlocks only after the user answers; unlocked items are
	// found again by the search that follows.
	if err := resolve(ctx, ss.bus, prompt); err != nil {
		return nil, err
	}
	return paths, nil
}

// find returns the items of account, unlocking them when the service holds
// them locked.
func (ss *secretSession) find(ctx context.Context, account string) ([]dbus.ObjectPath, error) {
	body, err := ss.bus.call(ctx, secretsPath, serviceIface+".SearchItems", attrsFor(account))
	if err != nil {
		return nil, fmt.Errorf("secret service: search: %w", err)
	}
	var unlocked, locked []dbus.ObjectPath
	if err := dbus.Store(body, &unlocked, &locked); err != nil {
		return nil, fmt.Errorf("secret service: search: %w", err)
	}
	if len(locked) == 0 {
		return unlocked, nil
	}
	more, err := ss.unlock(ctx, locked...)
	if err != nil {
		return nil, err
	}
	return append(unlocked, more...), nil
}

func (s *secretServiceIdentityStore) Load(account string) ([]byte, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	ss, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer ss.close()

	items, err := ss.find(ctx, account)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrIdentityNotFound
	}
	body, err := ss.bus.call(ctx, items[0], itemIface+".GetSecret", ss.path)
	if err != nil {
		return nil, fmt.Errorf("secret service: read: %w", err)
	}
	var sv secretValue
	if err := dbus.Store(body, &sv); err != nil {
		return nil, fmt.Errorf("secret service: read: %w", err)
	}
	plain, err := ss.open(sv)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	return decodeIdentity(plain)
}

func (s *secretServiceIdentityStore) Store(account string, identity []byte) error {
	if err := validAccount(account); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	ss, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer ss.close()

	body, err := ss.bus.call(ctx, secretsPath, serviceIface+".ReadAlias", "default")
	if err != nil {
		return fmt.Errorf("secret service: default collection: %w", err)
	}
	var collection dbus.ObjectPath
	if err := dbus.Store(body, &collection); err != nil || !collection.IsValid() || collection == noPrompt {
		return errors.New("secret service: there is no default collection to store the identity in")
	}
	if _, err := ss.unlock(ctx, collection); err != nil {
		return err
	}

	text := []byte(hex.EncodeToString(identity))
	defer clear(text)
	sv, err := ss.seal(text)
	if err != nil {
		return err
	}
	props := map[string]dbus.Variant{
		itemIface + ".Label":      dbus.MakeVariant(itemLabel),
		itemIface + ".Attributes": dbus.MakeVariant(attrsFor(account)),
	}
	body, err = ss.bus.call(ctx, collection, collectionIface+".CreateItem", props, sv, true)
	if err != nil {
		return fmt.Errorf("secret service: store: %w", err)
	}
	var item, prompt dbus.ObjectPath
	if err := dbus.Store(body, &item, &prompt); err != nil {
		return fmt.Errorf("secret service: store: %w", err)
	}
	return resolve(ctx, ss.bus, prompt)
}

func (s *secretServiceIdentityStore) Delete(account string) error {
	if err := validAccount(account); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	ss, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer ss.close()

	items, err := ss.find(ctx, account)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return ErrIdentityNotFound
	}
	for _, item := range items {
		body, err := ss.bus.call(ctx, item, itemIface+".Delete")
		if err != nil {
			return fmt.Errorf("secret service: delete: %w", err)
		}
		var prompt dbus.ObjectPath
		if err := dbus.Store(body, &prompt); err != nil {
			return fmt.Errorf("secret service: delete: %w", err)
		}
		if err := resolve(ctx, ss.bus, prompt); err != nil {
			return err
		}
	}
	return nil
}

// sessionBusConfigured reports whether a session bus is reachable: an
// explicit address, or the user's runtime-directory socket.
func sessionBusConfigured(getenv func(string) string) bool {
	if getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		return true
	}
	runtimeDir := getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(runtimeDir, "bus"))
	return err == nil
}

type dbusConn struct {
	conn  *dbus.Conn
	owner string
}

func connectSessionBus(ctx context.Context) (secretBus, error) {
	conn, err := dbus.ConnectSessionBus(dbus.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	var owner string
	if err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, secretsName).Store(&owner); err != nil {
		if call := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.StartServiceByName", 0, secretsName, uint32(0)); call.Err != nil {
			_ = conn.Close()
			return nil, call.Err
		}
		err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, secretsName).Store(&owner)
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &dbusConn{conn: conn, owner: owner}, nil
}

func (c *dbusConn) close() { _ = c.conn.Close() }

func (c *dbusConn) call(ctx context.Context, path dbus.ObjectPath, method string, args ...any) ([]any, error) {
	call := c.conn.Object(c.owner, path).CallWithContext(ctx, method, 0, args...)
	return call.Body, call.Err
}

func (c *dbusConn) prompt(ctx context.Context, path dbus.ObjectPath) (bool, error) {
	match := []dbus.MatchOption{
		dbus.WithMatchSender(c.owner), dbus.WithMatchObjectPath(path),
		dbus.WithMatchInterface(promptIface), dbus.WithMatchMember("Completed"),
	}
	if err := c.conn.AddMatchSignalContext(ctx, match...); err != nil {
		return false, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
		defer cancel()
		_ = c.conn.RemoveMatchSignalContext(cleanup, match...)
	}()
	signals := make(chan *dbus.Signal, 8)
	c.conn.Signal(signals)
	defer c.conn.RemoveSignal(signals)

	if _, err := c.call(ctx, path, promptIface+".Prompt", ""); err != nil {
		return false, err
	}
	for {
		select {
		case sig := <-signals:
			if sig == nil {
				return false, errors.New("secret service: bus closed while waiting for prompt")
			}
			if sig.Sender != c.owner || sig.Path != path || sig.Name != promptIface+".Completed" {
				continue
			}
			if len(sig.Body) != 2 {
				return false, errors.New("secret service: malformed prompt response")
			}
			dismissed, ok := sig.Body[0].(bool)
			if !ok {
				return false, errors.New("secret service: malformed prompt response")
			}
			return dismissed, nil
		case <-ctx.Done():
			dismissCtx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
			defer cancel()
			_, _ = c.call(dismissCtx, path, promptIface+".Dismiss")
			return false, fmt.Errorf("secret service: no answer to the prompt: %w", ctx.Err())
		}
	}
}
