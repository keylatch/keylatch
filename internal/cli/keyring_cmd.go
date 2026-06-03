package cli

// keyring_cmd.go implements the Phase 5 keyring management CLI commands.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
	filebe "github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// newKeyringCmd returns the `keylatch keyring` command group.
func newKeyringCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keyring",
		Short: "Manage the encryption keyring",
	}
	cmd.AddCommand(
		newKeyringInitCmd(),
		newKeyringRotateTermCmd(),
		newKeyringRotateKEKCmd(),
		newKeyringDestroyTermCmd(),
		newKeyringStatusCmd(),
	)
	return cmd
}

// newKeyringInitCmd implements `keylatch keyring init`.
func newKeyringInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize the encryption keyring",
		Long:  "Creates the keyring file and wraps the first DEK under the specified KEK.",
		RunE: func(cmd *cobra.Command, args []string) error {
			kekFlag, _ := cmd.Flags().GetString("kek")
			fips, _ := cmd.Flags().GetBool("fips")

			alg := envelope.XChaCha20Poly1305
			if fips {
				alg = envelope.AES256GCM
			}

			vaultDir := paths.Vault(os.Getenv)
			keyringDir := filepath.Join(vaultDir, "keyring")
			if err := os.MkdirAll(keyringDir, 0o700); err != nil {
				return fmt.Errorf("keyring init: mkdir: %w", err)
			}

			krPath := filepath.Join(keyringDir, "keyring.json")

			// Idempotent check.
			if _, err := os.Stat(krPath); err == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "keyring already initialized at", krPath)
				return nil
			}

			// Generate a random salt for passphrase KEK derivation. The salt
			// is stored in the keyring file so future passphrase derivations
			// use the same salt (Critical 4 fix).
			salt := make([]byte, 32)
			if _, err := cryptoRandRead(salt); err != nil {
				return fmt.Errorf("keyring init: generate salt: %w", err)
			}

			k, err := buildKEKWithSalt(cmd.Context(), kekFlag, salt)
			if err != nil {
				return fmt.Errorf("keyring init: %w", err)
			}

			var gcmLeaseSize uint64
			if alg == envelope.AES256GCM {
				gcmLeaseSize = 1024
			}

			// keyring.New handles atomic write (S5-19): temp file + fsync + rename.
			// This eliminates the divergent CLI init path (Warning 7).
			if err := keyring.NewWithSalt(krPath, k, alg, gcmLeaseSize, salt); err != nil {
				return fmt.Errorf("keyring init: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "keyring initialized at %s (algorithm: %s)\n", krPath, alg)
			return nil
		},
	}
	cmd.Flags().String("kek", "passphrase", "KEK type: passphrase|keychain|op:<vault>/<item>/<field>|bw:<id>/<field>|age-env")
	cmd.Flags().Bool("fips", false, "use AES-256-GCM (FIPS mode)")
	return cmd
}

// newKeyringRotateTermCmd implements `keylatch keyring rotate-term`.
func newKeyringRotateTermCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-term",
		Short: "Rotate to a new DEK term",
		RunE: func(cmd *cobra.Command, args []string) error {
			kr, k, krPath, err := openKeyringFromEnv()
			if err != nil {
				return fmt.Errorf("rotate-term: %w", err)
			}
			defer kr.Zero()
			_ = krPath

			newTerm, err := kr.RotateTerm(k)
			if err != nil {
				return fmt.Errorf("rotate-term: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "rotated to term %d\n", newTerm)
			return nil
		},
	}
}

// newKeyringRotateKEKCmd implements `keylatch keyring rotate-kek --new-kek=<type>`.
func newKeyringRotateKEKCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate-kek",
		Short: "Replace the KEK without changing DEKs",
		RunE: func(cmd *cobra.Command, args []string) error {
			newKEKSpec, _ := cmd.Flags().GetString("to")

			kr, _, _, err := openKeyringFromEnv()
			if err != nil {
				return fmt.Errorf("rotate-kek: %w", err)
			}
			defer kr.Zero()

			newKEK, err := buildKEK(cmd.Context(), newKEKSpec)
			if err != nil {
				return fmt.Errorf("rotate-kek: build new KEK: %w", err)
			}

			if err := kr.RotateKEK(newKEK); err != nil {
				return fmt.Errorf("rotate-kek: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "KEK rotated successfully")
			return nil
		},
	}
	cmd.Flags().String("to", "", "new KEK spec (required)")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

// newKeyringDestroyTermCmd implements `keylatch keyring destroy-term <n>`.
// S5-8: blocked in LLM sessions.
func newKeyringDestroyTermCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "destroy-term <n>",
		Short: "Permanently destroy a retired DEK term (irreversible)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// S5-8: block in LLM sessions.
			if llmcontext.IsLLMSession(os.Getenv) {
				return fmt.Errorf("destroy-term: blocked in LLM session (S5-8)")
			}

			termStr := args[0]
			term, err := strconv.Atoi(termStr)
			if err != nil {
				return fmt.Errorf("destroy-term: invalid term %q: %w", termStr, err)
			}

			kr, _, _, err := openKeyringFromEnv()
			if err != nil {
				return fmt.Errorf("destroy-term: %w", err)
			}
			defer kr.Zero()

			// Require confirmation.
			fmt.Fprintln(cmd.OutOrStdout(), "This is irreversible. All values encrypted under this term will become permanently unreadable.")
			fmt.Fprint(cmd.OutOrStdout(), "Type 'destroy' to confirm: ")
			var confirm string
			if _, err := fmt.Fscan(cmd.InOrStdin(), &confirm); err != nil || confirm != "destroy" {
				return fmt.Errorf("destroy-term: aborted")
			}

			if err := kr.DestroyTerm(term); err != nil {
				return fmt.Errorf("destroy-term: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "term %d destroyed\n", term)
			return nil
		},
	}
}

// newKeyringStatusCmd implements `keylatch keyring status`.
func newKeyringStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show keyring file summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, krPath, err := openKeyringFromEnv()
			if err != nil {
				return fmt.Errorf("status: %w", err)
			}

			data, err := os.ReadFile(krPath)
			if err != nil {
				return fmt.Errorf("status: read keyring: %w", err)
			}

			var kf keyring.KeyringFile
			if err := json.Unmarshal(data, &kf); err != nil {
				return fmt.Errorf("status: parse keyring: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "keyring: %s\n", krPath)
			fmt.Fprintf(cmd.OutOrStdout(), "algorithm: %s\n", kf.Algorithm)
			fmt.Fprintf(cmd.OutOrStdout(), "kek_type:  %s\n", kf.KEKType)
			fmt.Fprintf(cmd.OutOrStdout(), "active_term: %d\n", kf.ActiveTerm)
			fmt.Fprintf(cmd.OutOrStdout(), "terms:\n")
			for _, tr := range kf.Terms {
				fmt.Fprintf(cmd.OutOrStdout(), "  term %d: %s (created: %s)\n", tr.Term, tr.Status, tr.CreatedAt)
			}
			if kf.GCMState != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "gcm_nonce_counters:\n")
				for term, counter := range kf.GCMState.PerTerm {
					fmt.Fprintf(cmd.OutOrStdout(), "  term %d: %d\n", term, counter)
				}
			}
			return nil
		},
	}
}

// cryptoRandRead fills b with cryptographically random bytes.
func cryptoRandRead(b []byte) (int, error) {
	return rand.Read(b)
}

// newCryptoCmd returns the `keylatch crypto` command group.
func newCryptoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "crypto",
		Short: "Cryptographic utilities",
	}
	cmd.AddCommand(newCryptoCalibrateCmd())
	return cmd
}

// newCryptoCalibrateCmd implements `keylatch crypto calibrate`.
func newCryptoCalibrateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "calibrate",
		Short: "Calibrate Argon2id parameters for this machine",
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := argon2.Calibrate(2000) // 2-second target
			if err != nil {
				return fmt.Errorf("calibrate: %w", err)
			}
			out, _ := json.MarshalIndent(map[string]any{
				"time":     p.Time,
				"memory":   p.Memory,
				"threads":  p.Threads,
				"salt_len": p.SaltLen,
				"key_len":  p.KeyLen,
			}, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		},
	}
}

// buildKEK constructs a KEK from a spec string.
// For the passphrase spec, the salt is loaded from the existing keyring file.
// Use buildKEKWithSalt when the salt is already known (e.g. during init).
func buildKEK(ctx context.Context, spec string) (filebe.KEK, error) {
	if spec == "passphrase" || spec == "" {
		// Load the keyring file to obtain the persisted salt.
		vaultDir := paths.Vault(os.Getenv)
		krPath := filepath.Join(vaultDir, "keyring", "keyring.json")
		data, err := os.ReadFile(krPath)
		if err != nil {
			return nil, fmt.Errorf("passphrase KEK: read keyring for salt: %w", err)
		}
		var kf keyring.KeyringFile
		if err := json.Unmarshal(data, &kf); err != nil {
			return nil, fmt.Errorf("passphrase KEK: parse keyring: %w", err)
		}
		if len(kf.Salt) == 0 {
			return nil, fmt.Errorf("passphrase KEK: keyring file missing salt")
		}
		return buildKEKWithSalt(ctx, spec, kf.Salt)
	}
	return buildKEKWithSalt(ctx, spec, nil)
}

// buildKEKWithSalt constructs a KEK from a spec string using an explicit salt.
// salt is only used for the "passphrase" spec; other specs ignore it.
// Supported specs: "passphrase", "keychain", "op:<vault>/<item>/<field>",
// "bw:<id>/<field>", "age-env".
//
// S-FIND-12: the KEYLATCH_PASSPHRASE env-var read path is deleted. Passphrase
// input is accepted only via TTY (interactive prompt) or stdin pipe (@-).
// No code in this function reads KEYLATCH_PASSPHRASE.
func buildKEKWithSalt(_ context.Context, spec string, salt []byte) (filebe.KEK, error) {
	switch {
	case spec == "passphrase" || spec == "":
		// S-FIND-12: KEYLATCH_PASSPHRASE env var is NOT read here.
		// Passphrase must come from TTY or stdin pipe — read from os.Stdin.
		pass, err := readPassphrase()
		if err != nil {
			return nil, fmt.Errorf("passphrase KEK: read passphrase: %w", err)
		}
		if len(pass) == 0 {
			return nil, fmt.Errorf("passphrase KEK: empty passphrase")
		}
		if len(salt) == 0 {
			return nil, fmt.Errorf("passphrase KEK: salt must not be empty")
		}
		k, err := filebe.PassphraseKEK(pass, salt, argon2.Recommended2026)
		if err != nil {
			return nil, err
		}
		return k, nil
	case spec == "keychain":
		return filebe.KeychainKEK("keylatch-dek")
	case spec == "age-env":
		if len(salt) == 0 {
			// Fall back to loading from the keyring file.
			vaultDir := paths.Vault(os.Getenv)
			krPath := filepath.Join(vaultDir, "keyring", "keyring.json")
			data, err := os.ReadFile(krPath)
			if err != nil {
				return nil, fmt.Errorf("age-env: read keyring for salt: %w", err)
			}
			var kf keyring.KeyringFile
			if err := json.Unmarshal(data, &kf); err != nil {
				return nil, fmt.Errorf("age-env: parse keyring: %w", err)
			}
			salt = kf.Salt
		}
		return filebe.EnvAgeIdentityKEK(salt)
	case strings.HasPrefix(spec, "op:"):
		// parse "op:<vault>/<item>/<field>"
		parts := strings.SplitN(strings.TrimPrefix(spec, "op:"), "/", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("op KEK spec must be op:<vault>/<item>/<field>")
		}
		return filebe.OPKEK(parts[0], parts[1], parts[2])
	case strings.HasPrefix(spec, "bw:"):
		// parse "bw:<itemID>/<field>"
		parts := strings.SplitN(strings.TrimPrefix(spec, "bw:"), "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("bw KEK spec must be bw:<itemID>/<field>")
		}
		return filebe.BWKEK(parts[0], parts[1])
	default:
		return nil, fmt.Errorf("unsupported KEK spec: %q", spec)
	}
}

// readPassphrase reads a passphrase from a TTY (masked) or any non-TTY stdin
// source (anonymous pipe, named FIFO, file redirect, char device).
//
// S-FIND-12: KEYLATCH_PASSPHRASE env var is not used. If stdin is a TTY,
// term.ReadPassword is used for masked input. Otherwise, io.ReadAll reads the
// passphrase from whatever is connected to stdin — os.ModeNamedPipe is NOT
// used because it only detects named FIFOs and misses anonymous pipes (e.g.
// `echo "pass" | cmd`), breaking CI automation.
//
// If the result is empty (e.g. /dev/null or a closed pipe), a UsageError is
// returned so the caller gets a clear rejection rather than a silent empty
// passphrase attempt.
func readPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())

	// Branch 1: stdin is a TTY — use term.ReadPassword for masked input.
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Passphrase: ")
		pass, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr) // newline after masked input
		if err != nil {
			return nil, fmt.Errorf("read passphrase from TTY: %w", err)
		}
		return bytes.TrimRight(pass, "\r\n"), nil
	}

	// Branch 2: stdin is not a TTY (anonymous pipe, named FIFO, file redirect,
	// /dev/null, etc.) — read whatever is there and validate it is non-empty.
	// Using io.ReadAll instead of os.ModeNamedPipe because ModeNamedPipe only
	// matches named FIFOs and silently misses anonymous pipes on Linux.
	pass, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read passphrase from stdin: %w", err)
	}
	pass = bytes.TrimRight(pass, "\r\n")
	if len(pass) == 0 {
		// KEYLATCH_PASSPHRASE env var is not accepted (S-FIND-12).
		return nil, NewUsageError(
			"passphrase requires a TTY (for masked input) or stdin pipe with a non-empty passphrase. KEYLATCH_PASSPHRASE is not supported.",
		)
	}
	return pass, nil
}

// openKeyringFromEnv opens the audit keyring from the default path.
// Tries the bootstrap age identity (no user interaction) first, so that audit
// logging works automatically after `keylatch setup`. Falls back to passphrase
// for manually-initialized keyrings that require user input.
func openKeyringFromEnv() (*keyring.Keyring, filebe.KEK, string, error) {
	vaultDir := paths.Vault(os.Getenv)
	krPath := filepath.Join(vaultDir, "keyring", "keyring.json")

	// Read the salt from the existing keyring file so we can derive the right key.
	data, err := os.ReadFile(krPath)
	if err != nil {
		return nil, nil, "", fmt.Errorf("open keyring %q: %w", krPath, err)
	}
	var kf keyringFileForSalt
	if jsonErr := json.Unmarshal(data, &kf); jsonErr != nil || len(kf.Salt) == 0 {
		// No salt: fall through to passphrase.
		kf.Salt = nil
	}

	// Try age identity KEK (non-interactive: uses bootstrap identity file).
	identityPath := paths.KeyringIdentityPath(os.Getenv)
	if len(kf.Salt) > 0 {
		if k, kekErr := filebe.AgeIdentityKEKFromPath(identityPath, kf.Salt); kekErr == nil {
			if kr, openErr := keyring.Open(krPath, k); openErr == nil {
				return kr, k, krPath, nil
			}
		}
	}

	// Fall back to passphrase (manually initialized keyrings).
	k, err := buildKEK(context.Background(), "passphrase")
	if err != nil {
		return nil, nil, "", err
	}
	kr, err := keyring.Open(krPath, k)
	if err != nil {
		return nil, nil, "", fmt.Errorf("open keyring %q: %w", krPath, err)
	}
	return kr, k, krPath, nil
}

// keyringFileForSalt is a minimal struct for reading just the Salt field
// from a keyring.json without importing the full keyring package.
type keyringFileForSalt struct {
	Salt []byte `json:"salt"`
}
