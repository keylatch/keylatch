package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	kargon2 "github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caOpenBackup decrypts every credential entry in a backup archive with the
// passphrase, the way a restore would.
func caOpenBackup(t *testing.T, archive, passphrase string) (backupHeader, map[string]string) {
	t.Helper()
	fh, err := os.Open(archive)
	require.NoError(t, err)
	defer fh.Close()

	tr := tar.NewReader(fh)
	var hdr backupHeader
	raw := map[string][]byte{}
	for {
		th, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		assert.Equal(t, int64(0o600), th.Mode)
		data, err := io.ReadAll(tr)
		require.NoError(t, err)
		if th.Name == "keylatch-backup/header.json" {
			require.NoError(t, json.Unmarshal(data, &hdr))
			continue
		}
		raw[strings.TrimPrefix(th.Name, "keylatch-backup/")] = data
	}
	require.Equal(t, 1, hdr.Version)

	key, err := kargon2.Derive([]byte(passphrase), hdr.Argon2ID.Salt, kargon2.Params{
		Time: hdr.Argon2ID.Time, Memory: hdr.Argon2ID.Memory, Threads: hdr.Argon2ID.Threads,
		SaltLen: uint32(len(hdr.Argon2ID.Salt)), KeyLen: hdr.Argon2ID.KeyLen,
	})
	require.NoError(t, err)

	plain := map[string]string{}
	for name, blob := range raw {
		path := strings.ReplaceAll(name, "_", "/")
		pt, err := envelope.Open(envelope.XChaCha20Poly1305, key, blob[24:], blob[:24], []byte(path))
		require.NoError(t, err, name)
		plain[path] = string(pt)
	}
	return hdr, plain
}

func TestBackupCmdRestorableWithPassphraseFile(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	store := newDispatchedStore(f.cfg, f.env)
	ctx := context.Background()
	creds := map[string]string{
		"default/ai/openrouter/apikey": caSecret("openrouter"),
		"default/ai/anthropic/token":   caSecret("anthropic"),
	}
	for p, v := range creds {
		require.NoError(t, store.Set(ctx, p, []byte(v), backend.Meta{}))
	}
	require.NoError(t, store.Set(ctx, "default/ai/anthropic/meta", []byte(`{"provider":"anthropic"}`), backend.Meta{}))

	dir := t.TempDir()
	passFile := filepath.Join(dir, "pass")
	const pass = "backup pass phrase"
	require.NoError(t, os.WriteFile(passFile, []byte(pass+"\r\n"), 0o600))
	archive := filepath.Join(dir, "out.enc")

	out, errOut, err := caRun(t, nil, "backup", "--output", archive, "--passphrase-file", passFile)
	require.NoError(t, err, errOut)
	assert.Contains(t, out, "backed up 2 connection(s) to "+archive)
	for _, v := range creds {
		assert.NotContains(t, out+errOut, v)
	}

	rawArchive, err := os.ReadFile(archive)
	require.NoError(t, err)
	for _, v := range creds {
		assert.False(t, bytes.Contains(rawArchive, []byte(v)), "archive must not contain plaintext credentials")
	}

	_, restored := caOpenBackup(t, archive, pass)
	assert.Equal(t, creds, restored)
}

func TestBackupCmdDefaultOutputName(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	work := t.TempDir()
	t.Chdir(work)
	passFile := filepath.Join(t.TempDir(), "pass")
	require.NoError(t, os.WriteFile(passFile, []byte("pw"), 0o600))

	out, _, err := caRun(t, nil, "backup", "--passphrase-file", passFile)
	require.NoError(t, err)
	assert.Contains(t, out, "backed up 0 connection(s) to keylatch-backup-")
	matches, err := filepath.Glob(filepath.Join(work, "keylatch-backup-*.enc"))
	require.NoError(t, err)
	require.Len(t, matches, 1)
	hdr, plain := caOpenBackup(t, matches[0], "pw")
	assert.Empty(t, plain)
	assert.Len(t, hdr.Argon2ID.Salt, int(kargon2.Recommended2026.SaltLen))
}

func TestBackupCmdBlockedInLLMSessionListsReasons(t *testing.T) {
	caNewVault(t, envelope.XChaCha20Poly1305)
	caSetLLMSession(t)
	archive := filepath.Join(t.TempDir(), "out.enc")
	_, _, err := caRun(t, nil, "backup", "--output", archive, "--passphrase-file", "/nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "blocked in LLM sessions")
	assert.Contains(t, err.Error(), "detected via: ")
	_, statErr := os.Stat(archive)
	assert.True(t, os.IsNotExist(statErr))
}

type caBackupStore struct {
	entries []backend.Entry
	values  map[string]string
	listErr error
	gets    []string
}

func (s *caBackupStore) List(_ context.Context, _ string) ([]backend.Entry, error) {
	return s.entries, s.listErr
}

func (s *caBackupStore) Get(_ context.Context, p string) ([]byte, backend.Meta, error) {
	s.gets = append(s.gets, p)
	v, ok := s.values[p]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return []byte(v), backend.Meta{}, nil
}

func TestWriteBackupSkipsMetadataDuplicatesAndUnreadable(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	salt := bytes.Repeat([]byte{1}, 32)
	store := &caBackupStore{
		entries: []backend.Entry{
			{Meta: backend.Meta{Path: "default/ai/a/key"}},
			{Meta: backend.Meta{Path: "default/ai/a/key"}},
			{Meta: backend.Meta{Path: "default/ai/a/meta"}},
			{Meta: backend.Meta{Path: "default/ai/a/meta/extra"}},
			{Meta: backend.Meta{Path: "default/ai/a/config/url"}},
			{Meta: backend.Meta{Path: "default/ai/gone/key"}},
		},
		values: map[string]string{"default/ai/a/key": "value-a"},
	}
	var warn bytes.Buffer
	out := filepath.Join(t.TempDir(), "b.enc")
	n, err := writeBackupToFile(context.Background(), &warn, store, out, key, salt)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, []string{"default/ai/a/key", "default/ai/gone/key"}, store.gets)
	assert.Contains(t, warn.String(), "warning: skipping default/ai/gone/key")
}

func TestWriteBackupErrors(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	_, err := writeBackupToFile(context.Background(), io.Discard,
		&caBackupStore{listErr: errors.New("backend down")}, filepath.Join(t.TempDir(), "x"), key, []byte("s"))
	assert.ErrorContains(t, err, "list connections: backend down")

	_, err = writeBackupToFile(context.Background(), io.Discard,
		&caBackupStore{}, filepath.Join(t.TempDir(), "missing", "dir", "x"), key, []byte("s"))
	assert.ErrorContains(t, err, "create backup file")

	_, err = writeBackupToFile(context.Background(), io.Discard,
		&caBackupStore{entries: []backend.Entry{{Meta: backend.Meta{Path: "default/ai/a/key"}}}, values: map[string]string{"default/ai/a/key": "v"}},
		filepath.Join(t.TempDir(), "x"), []byte("short"), []byte("s"))
	assert.ErrorContains(t, err, `seal credential "default/ai/a/key"`)
}

func TestDispatchedStoreSetGetListDelete(t *testing.T) {
	f := caNewVault(t, envelope.XChaCha20Poly1305)
	s := newDispatchedStore(f.cfg, f.env)
	ctx := context.Background()
	p := "default/ai/openrouter/token"
	require.NoError(t, s.Set(ctx, p, []byte("v1"), backend.Meta{}))
	got, _, err := s.Get(ctx, p)
	require.NoError(t, err)
	assert.Equal(t, "v1", string(got))
	entries, err := s.List(ctx, "default/ai/")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.NoError(t, s.Delete(ctx, p))
	_, _, err = s.Get(ctx, p)
	assert.ErrorIs(t, err, backend.ErrNotFound)
}

func TestDispatchedStoreBackendUnavailable(t *testing.T) {
	f := caNewEnv(t)
	s := newDispatchedStore(f.cfg, f.env)
	ctx := context.Background()
	_, _, err := s.Get(ctx, "a/b/c/d")
	assert.ErrorIs(t, err, backend.ErrBootstrapRequired)
	assert.ErrorIs(t, s.Set(ctx, "a/b/c/d", []byte("v"), backend.Meta{}), backend.ErrBootstrapRequired)
	_, err = s.List(ctx, "")
	assert.ErrorIs(t, err, backend.ErrBootstrapRequired)
	assert.ErrorIs(t, s.Delete(ctx, "a/b/c/d"), backend.ErrBootstrapRequired)
}
