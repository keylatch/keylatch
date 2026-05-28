// Package cli — backup command (T-12-02).
package cli

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	kargon2 "github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/spf13/cobra"
)

// newBackupCmd returns the `keylatch backup` subcommand.
//
// T-12-02: backup is value-bearing (it reads credentials) and is blocked in
// LLM sessions (exit 2). Passphrase comes from a TTY prompt, never from argv.
func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Export an encrypted backup of all enrolled connections",
		Long: `backup writes all enrolled connection credentials to an
xchacha20-poly1305 encrypted tar archive derived from a backup passphrase.

The passphrase is prompted interactively from the terminal and is never
exposed on the command line. The output file is safe to store off-site.

To restore from backup, use: keylatch restore <backup-file>`,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()
			env := llmcontext.DefaultLookup

			// T-12-02: value-bearing — blocked in LLM sessions (exit 2).
			if llmcontext.IsLLMSession(env) {
				reasons := llmcontext.Reasons(env)
				fmt.Fprintf(c.ErrOrStderr(), "Error: backup is blocked in LLM sessions (value-bearing operation).\n")
				if len(reasons) > 0 {
					fmt.Fprintf(c.ErrOrStderr(), "  Detected via: %s\n", strings.Join(reasons, ", "))
				}
				return fmt.Errorf("[keylatch] security block: backup is blocked in LLM sessions (exit %d)", exitcode.SecurityBlock)
			}

			outputPath, _ := c.Flags().GetString("output")
			passphraseFile, _ := c.Flags().GetString("passphrase-file")

			// Resolve output path.
			if outputPath == "" {
				ts := time.Now().UTC().Format("2006-01-02T15-04-05Z")
				outputPath = "keylatch-backup-" + ts + ".enc"
			}

			// Read passphrase.
			var passphrase []byte
			if passphraseFile != "" {
				data, err := os.ReadFile(passphraseFile)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: reading passphrase file %q: %v\n", passphraseFile, err)
					os.Exit(exitcode.UserError)
					return nil
				}
				passphrase = []byte(strings.TrimRight(string(data), "\r\n"))
			} else {
				if !stdinIsTTY() {
					fmt.Fprintln(c.ErrOrStderr(), "Error: backup passphrase requires a TTY. Use --passphrase-file to provide a passphrase non-interactively.")
					os.Exit(exitcode.UserError)
					return nil
				}
				var err error
				passphrase, err = promptHidden("Enter backup passphrase")
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
					os.Exit(exitcode.UserError)
					return nil
				}
				confirm, err := promptHidden("Confirm backup passphrase")
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
					os.Exit(exitcode.UserError)
					return nil
				}
				if subtle.ConstantTimeCompare(passphrase, confirm) != 1 {
					fmt.Fprintln(c.ErrOrStderr(), "Error: passphrases do not match.")
					os.Exit(exitcode.UserError)
					return nil
				}
			}

			// Derive backup KEK via argon2id.
			salt := make([]byte, kargon2.Recommended2026.SaltLen)
			if _, err := rand.Read(salt); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: generating backup salt: %v\n", err)
				os.Exit(exitcode.OperationFailed)
				return nil
			}
			kek, err := kargon2.Derive(passphrase, salt, kargon2.Recommended2026)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: deriving backup KEK: %v\n", err)
				os.Exit(exitcode.OperationFailed)
				return nil
			}
			// Zero passphrase from memory once KEK is derived.
			for i := range passphrase {
				passphrase[i] = 0
			}

			// Collect connection credentials.
			cfg := loadCLIConfig(c)
			store := newDispatchedStore(cfg, env)
			n, err := writeBackupToFile(ctx, c.ErrOrStderr(), store, outputPath, kek, salt)
			if err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "Error: %v\n", err)
				os.Exit(exitcode.OperationFailed)
				return nil
			}

			fmt.Fprintf(c.OutOrStdout(), "backed up %d connection(s) to %s\n", n, outputPath)
			return nil
		},
	}
	cmd.Flags().String("output", "", "output file path (default: keylatch-backup-<timestamp>.enc in cwd)")
	cmd.Flags().String("passphrase-file", "", "read backup passphrase from this file instead of prompting")
	return cmd
}

// backupHeader is serialised as the first entry in the backup archive.
// It carries the argon2id salt and parameters so restore can re-derive the KEK.
type backupHeader struct {
	Version   int    `json:"version"`
	Timestamp string `json:"timestamp"`
	Argon2ID  struct {
		Salt    []byte `json:"salt"`
		Time    uint32 `json:"time"`
		Memory  uint32 `json:"memory"`
		Threads uint8  `json:"threads"`
		KeyLen  uint32 `json:"key_len"`
	} `json:"argon2id"`
}

// backupCredStore is the minimal interface needed for writeBackupToFile.
// Satisfied by *dispatchedStore in production and test mocks.
type backupCredStore interface {
	List(ctx context.Context, prefix string) ([]backend.Entry, error)
	Get(ctx context.Context, path string) ([]byte, backend.Meta, error)
}

// writeBackupToFile builds the encrypted tar archive and writes it to outputPath.
// Returns the number of credentials backed up.
//
// Archive structure:
//
//	keylatch-backup/header.json     — backupHeader (plaintext; no secrets)
//	keylatch-backup/<sanitized-path> — xchacha20-poly1305 ciphertext of raw credential
func writeBackupToFile(ctx context.Context, warnOut interface {
	Write([]byte) (int, error)
}, store backupCredStore, outputPath string, kek, salt []byte) (int, error) {
	// Build header.
	hdr := backupHeader{
		Version:   1,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	hdr.Argon2ID.Salt = salt
	hdr.Argon2ID.Time = kargon2.Recommended2026.Time
	hdr.Argon2ID.Memory = kargon2.Recommended2026.Memory
	hdr.Argon2ID.Threads = kargon2.Recommended2026.Threads
	hdr.Argon2ID.KeyLen = kargon2.Recommended2026.KeyLen

	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		return 0, fmt.Errorf("marshal backup header: %w", err)
	}

	// List connections using canonical ai category prefix (S-FIND-23).
	entries, err := store.List(ctx, "default/ai/")
	if err != nil {
		return 0, fmt.Errorf("list connections: %w", err)
	}

	// Gather unique credential paths (skip meta and config paths).
	seenPaths := map[string]bool{}
	var credPaths []string
	for _, e := range entries {
		p := e.Path
		if strings.HasSuffix(p, "/meta") || strings.Contains(p, "/meta/") {
			continue
		}
		if strings.Contains(p, "/config/") {
			continue
		}
		if seenPaths[p] {
			continue
		}
		seenPaths[p] = true
		credPaths = append(credPaths, p)
	}

	// Create output file.
	f, err := os.Create(outputPath)
	if err != nil {
		return 0, fmt.Errorf("create backup file %q: %w", outputPath, err)
	}
	defer func() { _ = f.Close() }()

	tw := tar.NewWriter(f)
	defer func() { _ = tw.Close() }()

	// Write header entry.
	if err := tw.WriteHeader(&tar.Header{
		Name:    "keylatch-backup/header.json",
		Size:    int64(len(hdrBytes)),
		Mode:    0o600,
		ModTime: time.Now(),
	}); err != nil {
		return 0, fmt.Errorf("write tar header entry: %w", err)
	}
	if _, err := tw.Write(hdrBytes); err != nil {
		return 0, fmt.Errorf("write tar header data: %w", err)
	}

	n := 0
	for _, credPath := range credPaths {
		// Read raw credential.
		value, _, err := store.Get(ctx, credPath)
		if err != nil {
			// Best-effort: skip credentials that cannot be read.
			fmt.Fprintf(warnOut, "warning: skipping %s: %v\n", credPath, err)
			continue
		}

		// Encrypt with xchacha20-poly1305. AAD = path (binds ciphertext to credential identity).
		ct, nonce, err := envelope.SealXChaCha20(kek, value, []byte(credPath))
		if err != nil {
			// Zero plaintext before returning error.
			for i := range value {
				value[i] = 0
			}
			return 0, fmt.Errorf("seal credential %q: %w", credPath, err)
		}
		// Zero plaintext from memory.
		for i := range value {
			value[i] = 0
		}

		// Combine nonce + ciphertext into the on-disk blob.
		sealed := make([]byte, len(nonce)+len(ct))
		copy(sealed, nonce)
		copy(sealed[len(nonce):], ct)

		// Sanitise path for tar entry name.
		entryName := "keylatch-backup/" + backupSanitizePath(credPath)
		if err := tw.WriteHeader(&tar.Header{
			Name:    entryName,
			Size:    int64(len(sealed)),
			Mode:    0o600,
			ModTime: time.Now(),
		}); err != nil {
			return 0, fmt.Errorf("write tar entry header for %q: %w", credPath, err)
		}
		if _, err := tw.Write(sealed); err != nil {
			return 0, fmt.Errorf("write tar entry data for %q: %w", credPath, err)
		}
		n++
	}

	return n, nil
}

// backupSanitizePath converts a vault canonical path to a safe tar entry name.
// Rejects paths containing ".." traversal sequences before any normalization,
// then replaces slashes with underscores.
func backupSanitizePath(p string) string {
	// Reject traversal sequences before any normalization so the check
	// operates on the original path, not a transformed variant.
	if strings.Contains(p, "..") {
		return "__invalid__"
	}
	safe := strings.ReplaceAll(p, "/", "_")
	return safe
}
