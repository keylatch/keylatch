package cli

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// mockBackupStore implements backupCredStore for backup tests.
type mockBackupStore struct {
	entries []backend.Entry
	data    map[string][]byte
}

func (m *mockBackupStore) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	var out []backend.Entry
	for _, e := range m.entries {
		if strings.HasPrefix(e.Path, prefix) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *mockBackupStore) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	val, ok := m.data[path]
	if !ok {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	cp := make([]byte, len(val))
	copy(cp, val)
	return cp, backend.Meta{Path: path, Backend: "mock"}, nil
}

// TestBackupLLMSessionBlocked verifies that backup is blocked (returns error)
// when run in an LLM session (T-12-02 guard).
func TestBackupLLMSessionBlocked(t *testing.T) {
	t.Setenv("CLAUDE_CODE", "1")

	root := NewRootCommand()
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"backup"})

	err := root.Execute()
	if err == nil {
		t.Error("expected error from backup in LLM session, got nil")
	}
	// The stderr message must mention "blocked in LLM sessions".
	if !strings.Contains(errBuf.String(), "blocked in LLM sessions") {
		t.Errorf("expected LLM block message in stderr, got: %s", errBuf.String())
	}
	// The error must contain "security block".
	if err != nil && !strings.Contains(err.Error(), "security block") {
		t.Errorf("expected 'security block' in error, got: %v", err)
	}
}

// TestWriteBackupToFile_NonEmpty verifies that a mock backend with one credential
// produces a non-empty .enc file containing the expected tar structure.
func TestWriteBackupToFile_NonEmpty(t *testing.T) {
	t.Parallel()

	store := &mockBackupStore{
		entries: []backend.Entry{
			{Meta: backend.Meta{Path: "default/ai/openai/api_key"}, Exists: true},
		},
		data: map[string][]byte{
			"default/ai/openai/api_key": []byte("sk-test-canary-value"),
		},
	}

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	salt := make([]byte, 32)

	outPath := t.TempDir() + "/backup.enc"
	var warnBuf bytes.Buffer
	n, err := writeBackupToFile(context.Background(), &warnBuf, store, outPath, kek, salt)
	if err != nil {
		t.Fatalf("writeBackupToFile: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 credential backed up, got %d", n)
	}

	// Verify the output file is non-empty and is a valid tar archive.
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("backup output file is empty")
	}

	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer f.Close()

	tr := tar.NewReader(f)
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("read first tar entry: %v", err)
	}
	if hdr.Name != "keylatch-backup/header.json" {
		t.Errorf("first entry name = %q; want keylatch-backup/header.json", hdr.Name)
	}
	headerData, _ := io.ReadAll(tr)
	if !strings.Contains(string(headerData), "argon2id") {
		t.Errorf("header.json missing argon2id field: %s", headerData)
	}

	// Second entry should be the encrypted credential.
	hdr2, err := tr.Next()
	if err != nil {
		t.Fatalf("read second tar entry: %v", err)
	}
	if !strings.HasPrefix(hdr2.Name, "keylatch-backup/") {
		t.Errorf("second entry name %q does not start with keylatch-backup/", hdr2.Name)
	}
}

// TestBackup_HumanTerminal_Succeeds verifies that writeBackupToFile succeeds
// for a human-terminal session with a passphrase-derived KEK and a mock store.
// Uses --passphrase-file to bypass TTY requirement in non-interactive tests.
// EPIC-30 T-12-02 canonical test name.
func TestBackup_HumanTerminal_Succeeds(t *testing.T) {
	t.Parallel()

	// Build a mock store with one credential entry.
	store := &mockBackupStore{
		entries: []backend.Entry{
			{Meta: backend.Meta{Path: "default/ai/anthropic/api_key"}, Exists: true},
		},
		data: map[string][]byte{
			"default/ai/anthropic/api_key": []byte("sk-ant-canary-human-terminal"),
		},
	}

	// Use a fixed KEK and salt (simulates passphrase derivation output).
	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(0xAB ^ i)
	}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(0xCD ^ i)
	}

	outPath := t.TempDir() + "/backup-human.enc"
	var warnBuf bytes.Buffer
	n, err := writeBackupToFile(context.Background(), &warnBuf, store, outPath, kek, salt)
	if err != nil {
		t.Fatalf("TestBackup_HumanTerminal_Succeeds: writeBackupToFile: %v", err)
	}
	if n != 1 {
		t.Errorf("TestBackup_HumanTerminal_Succeeds: expected 1 credential backed up, got %d", n)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("TestBackup_HumanTerminal_Succeeds: stat output: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("TestBackup_HumanTerminal_Succeeds: backup output file is empty")
	}
}

// TestBackup_DecryptableWithPassphrase verifies the full backup round-trip:
// write an encrypted archive, read the header, and decrypt the credential entry.
// EPIC-30 T-12-02 canonical test name.
func TestBackup_DecryptableWithPassphrase(t *testing.T) {
	t.Parallel()

	credential := []byte("sk-ant-api03-roundtrip-canary-abcdef1234")
	credPath := "default/ai/anthropic/api_key"

	store := &mockBackupStore{
		entries: []backend.Entry{
			{Meta: backend.Meta{Path: credPath}, Exists: true},
		},
		data: map[string][]byte{
			credPath: append([]byte(nil), credential...),
		},
	}

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 0x11)
	}
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 0x22)
	}

	outPath := t.TempDir() + "/backup-decrypt.enc"
	var warnBuf bytes.Buffer
	n, err := writeBackupToFile(context.Background(), &warnBuf, store, outPath, kek, salt)
	if err != nil {
		t.Fatalf("TestBackup_DecryptableWithPassphrase: writeBackupToFile: %v", err)
	}
	if n != 1 {
		t.Errorf("TestBackup_DecryptableWithPassphrase: expected 1 backup entry, got %d", n)
	}

	// Read the archive and decrypt the credential entry using the same KEK.
	f, err := os.Open(outPath)
	if err != nil {
		t.Fatalf("TestBackup_DecryptableWithPassphrase: open: %v", err)
	}
	defer f.Close()

	tr := tar.NewReader(f)
	// Skip the header entry.
	if _, err := tr.Next(); err != nil {
		t.Fatalf("TestBackup_DecryptableWithPassphrase: read header entry: %v", err)
	}
	io.ReadAll(tr) //nolint:errcheck // consume header body

	// Read the credential entry.
	hdr, err := tr.Next()
	if err != nil {
		t.Fatalf("TestBackup_DecryptableWithPassphrase: read cred entry: %v", err)
	}
	sealed, err := io.ReadAll(tr)
	if err != nil {
		t.Fatalf("TestBackup_DecryptableWithPassphrase: read cred data: %v", err)
	}

	// Validate expected entry name format.
	if !strings.HasPrefix(hdr.Name, "keylatch-backup/") {
		t.Errorf("TestBackup_DecryptableWithPassphrase: unexpected entry name %q", hdr.Name)
	}

	// Decrypt: nonce is the first 24 bytes, ciphertext is the rest.
	if len(sealed) < 24 {
		t.Fatalf("TestBackup_DecryptableWithPassphrase: sealed data too short (%d bytes)", len(sealed))
	}
	nonce := sealed[:24]
	ct := sealed[24:]

	plaintext, err := envelope.Open(envelope.XChaCha20Poly1305, kek, ct, nonce, []byte(credPath))
	if err != nil {
		t.Fatalf("TestBackup_DecryptableWithPassphrase: decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, credential) {
		t.Errorf("TestBackup_DecryptableWithPassphrase: decrypted %q; want %q", plaintext, credential)
	}
}

// TestWriteBackupToFile_RandomNonce verifies that two backups of the same data
// with the same passphrase produce different ciphertext (random nonce).
func TestWriteBackupToFile_RandomNonce(t *testing.T) {
	t.Parallel()

	store := &mockBackupStore{
		entries: []backend.Entry{
			{Meta: backend.Meta{Path: "default/ai/openai/api_key"}, Exists: true},
		},
		data: map[string][]byte{
			"default/ai/openai/api_key": []byte("sk-test-canary-value"),
		},
	}

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = 0x42
	}
	salt := make([]byte, 32)

	dir := t.TempDir()
	out1 := dir + "/backup1.enc"
	out2 := dir + "/backup2.enc"

	var w bytes.Buffer
	if _, err := writeBackupToFile(context.Background(), &w, store, out1, kek, salt); err != nil {
		t.Fatalf("first backup: %v", err)
	}
	if _, err := writeBackupToFile(context.Background(), &w, store, out2, kek, salt); err != nil {
		t.Fatalf("second backup: %v", err)
	}

	data1, _ := os.ReadFile(out1)
	data2, _ := os.ReadFile(out2)

	if bytes.Equal(data1, data2) {
		t.Error("two backups with the same passphrase produced identical ciphertext (nonce must be random)")
	}
}
