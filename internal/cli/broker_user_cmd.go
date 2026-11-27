package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/vault"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// userSource is the in-user install `broker adopt` moves into the daemon.
type userSource struct {
	cfg config.Config
	env llmcontext.Lookup
}

func newUserSource(c *cobra.Command, env llmcontext.Lookup) *userSource {
	return &userSource{cfg: loadCLIConfig(c), env: env}
}

// Secrets decrypts every secret in the configured backend.
func (s *userSource) Secrets(ctx context.Context) ([]brokerapi.Item, error) {
	store := newDispatchedStore(s.cfg, s.env)
	entries, err := store.List(ctx, "")
	if err != nil {
		return nil, err
	}
	var items []brokerapi.Item
	for _, e := range entries {
		if !e.Exists {
			continue
		}
		v, _, err := store.Get(ctx, e.Path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Path, err)
		}
		items = append(items, brokerapi.Item{Path: e.Path, Value: v})
	}
	return items, nil
}

// PolicyFiles returns policy.json and the connection policy documents.
func (s *userSource) PolicyFiles() (map[string][]byte, error) {
	files := map[string][]byte{}
	if b, err := os.ReadFile(paths.Policy(s.env)); err == nil {
		files["policy.json"] = b
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	docs, err := os.ReadDir(paths.PolicyDir(s.env))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, d := range docs {
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(paths.PolicyDir(s.env), d.Name()))
		if err != nil {
			return nil, err
		}
		files["policy.d/"+d.Name()] = b
	}
	if len(files) == 0 {
		return nil, nil
	}
	if _, ok := files["policy.json"]; !ok {
		files["policy.json"] = []byte(`{"default_deny":true}`)
	}
	return files, nil
}

// AuditHead returns the hash of the in-user chain's last entry, or "" when
// there is no log.
func (s *userSource) AuditHead() (string, error) {
	if _, err := os.Stat(paths.Audit(s.env)); err != nil {
		return "", nil
	}
	keys, err := auditKeysForRead("broker adopt")
	if err != nil {
		return "", err
	}
	defer keys.zero()
	head, err := audit.ReadHead(paths.Audit(s.env), keys.seed)
	if err != nil {
		return "", nil
	}
	return head.Hash, nil
}

// RevokeTokens revokes every live in-user gateway token.
func (s *userSource) RevokeTokens(context.Context) (int, error) {
	store := paths.GatewayTokens(s.env)
	if _, err := os.Stat(store); err != nil {
		return 0, nil
	}
	key, err := LoadGatewaySigningKey(s.env, false)
	if err != nil {
		return 0, nil
	}
	defer clear(key)
	live, err := token.List(token.ListOpts{}, store)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, t := range live {
		if err := token.Revoke(t.ID, store, key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Shred overwrites and removes the in-user key material the daemon replaces.
func (s *userSource) Shred() ([]string, error) {
	var gone []string
	for _, f := range []struct{ name, path string }{
		{"identity", paths.KeyringIdentityPath(s.env)},
		{"keyring.json", paths.KeyringPath(s.env)},
		{"keyring.json (legacy)", paths.LegacyKeyringPath(s.env)},
		{"signing.key", paths.GatewaySigningKey(s.env)},
		{"signing.key.enc", paths.GatewaySigningKeyWrapped(s.env)},
		{"audit-salt", paths.AuditSalt(s.env)},
		{"audit-key.enc", paths.AuditKeyWrapped(s.env)},
	} {
		ok, err := shredFile(f.path)
		if err != nil {
			return gone, fmt.Errorf("%s: %w", f.name, err)
		}
		if ok {
			gone = append(gone, f.name)
		}
	}
	return gone, nil
}

// shredFile overwrites a file with zeros before removing it.
func shredFile(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode().IsRegular() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return false, err
		}
		_, werr := f.Write(make([]byte, info.Size()))
		serr := f.Sync()
		cerr := f.Close()
		if err := errors.Join(werr, serr, cerr); err != nil {
			return false, err
		}
	}
	return true, os.Remove(path)
}

// userSink restores secrets into an in-user install.
type userSink struct {
	cfg     config.Config
	env     llmcontext.Lookup
	logger  *audit.Logger
	cleanup func()
}

func newUserSink(c *cobra.Command, env llmcontext.Lookup) (*userSink, func(), error) {
	s := &userSink{cfg: loadCLIConfig(c), env: env, cleanup: func() {}}
	return s, func() { s.cleanup() }, nil
}

// Prepare creates the in-user keyring, policy and audit log when missing.
func (s *userSink) Prepare(ctx context.Context) error {
	if _, err := bootstrap.Run(ctx, bootstrap.Options{
		Backend:         "file",
		Env:             s.env,
		Confirm:         true,
		InsecureFileKEK: insecureFileKEKAllowed(),
		Passphrase:      vaultPassphraseOption(),
	}); err != nil {
		return err
	}
	if _, err := ensureDefaultPolicy(); err != nil {
		return err
	}
	l, cleanup, err := requireAuditLogger("broker export-to-user")
	if err != nil {
		return err
	}
	s.logger, s.cleanup = l, cleanup
	return nil
}

// Put writes one secret as the next version of its path.
func (s *userSink) Put(ctx context.Context, path string, value []byte) error {
	ctx = audit.WithEmitter(ctx, audit.AsEmitter(s.logger))
	_, err := vault.RotateValue(ctx, path, value, vmeta.Meta{}, s.cfg, s.env)
	return err
}
