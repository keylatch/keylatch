package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/keylatch/keylatch/internal/backend/file"
	"github.com/keylatch/keylatch/internal/bootstrap"
	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/crypto/keyring"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/spf13/cobra"
)

// keysIdentityStore is the OS keyring the vault identity lives in. Replaced in
// tests.
var keysIdentityStore = kek.DefaultIdentityStore

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Show and change how the vault key is protected",
	}
	cmd.AddCommand(newKeysStatusCmd(), newKeysRewrapCmd())
	return cmd
}

// keysStatus is the `keys status --json` document. It names where the key is
// held and never contains key material.
type keysStatus struct {
	// KEKType is the keyring's key-encryption key type: age-env (an identity
	// held in the OS keyring or a file), passphrase, keychain, op or bw.
	KEKType string `json:"kek_type"`
	// Held is where the key-encryption key lives: os-keyring, passphrase,
	// plaintext-file or external.
	Held string `json:"held"`
	// PlaintextKEK is true while a plaintext identity file is on disk, whether
	// or not it is the one in use.
	PlaintextKEK bool   `json:"plaintext_kek"`
	Keyring      string `json:"keyring"`
}

type keyState struct {
	krPath   string
	header   keyring.KeyringFile
	identity kek.VaultIdentity
	loc      kek.IdentityLocation
	onDisk   bool
}

func loadKeyState() (*keyState, error) {
	env := llmcontext.DefaultLookup
	krPath := paths.ResolveKeyringPath(env)
	header, err := keyring.ReadHeader(krPath)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyringNotFound) {
			return nil, NewUsageError("keys: no keyring at %s; run `keylatch bootstrap` first", krPath)
		}
		return nil, fmt.Errorf("keys: %w", err)
	}
	vi := kek.VaultIdentity{Path: paths.KeyringIdentityPath(env), Store: keysIdentityStore()}
	loc, onDisk, err := vi.Location()
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	return &keyState{krPath: krPath, header: header, identity: vi, loc: loc, onDisk: onDisk}, nil
}

func (s *keyState) status() keysStatus {
	st := keysStatus{KEKType: s.header.KEKType, Keyring: s.krPath, PlaintextKEK: s.onDisk}
	switch s.header.KEKType {
	case "passphrase":
		st.Held = "passphrase"
	case "age-env":
		if s.loc == kek.IdentityInKeyring {
			st.Held = "os-keyring"
		} else {
			st.Held = "plaintext-file"
		}
	default:
		st.Held = "external"
	}
	return st
}

func newKeysStatusCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "status [--json]",
		Short: "Show where the vault key is held",
		Long: `Show where the key-encryption key is held and whether a plaintext copy is on
disk (plaintext_kek). Nothing is changed and no key material is shown.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			s, err := loadKeyState()
			if err != nil {
				return err
			}
			st := s.status()
			if jsonOut {
				b, _ := json.MarshalIndent(st, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}
			fmt.Fprintf(c.OutOrStdout(), "key-encryption key: %s (%s)\nplaintext copy on disk: %v\n", st.Held, st.KEKType, st.PlaintextKEK)
			if st.PlaintextKEK {
				fmt.Fprintln(c.OutOrStdout(), "Move it with: keylatch keys rewrap --to keystore|passphrase")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "output as JSON")
	return cmd
}

func newKeysRewrapCmd() *cobra.Command {
	var to string
	cmd := &cobra.Command{
		Use:   "rewrap --to keystore|passphrase",
		Short: "Move the vault key to the OS keyring or under a passphrase",
		Long: `Re-wrap the vault's data keys under a new key-encryption key held in the OS
keyring (keystore) or derived from a passphrase typed on the terminal
(passphrase). A fresh key is generated, so a copy of the old plaintext identity
no longer opens anything.

Before anything is deleted, keylatch proves the new key alone opens the keyring
and reads every secret. Only then is the plaintext identity overwritten with
random bytes and removed. If the proof fails the vault stays under its previous
key. Needs a human at a terminal.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if to != bootstrapKEKKeystore && to != bootstrapKEKPassphrase {
				return NewUsageError("keys rewrap: --to must be %s or %s", bootstrapKEKKeystore, bootstrapKEKPassphrase)
			}
			if _, err := requirePresence(c.Context(), presence.ActionKeysRewrap, "Re-wrap the vault key into the %s", to); err != nil {
				return err
			}
			s, err := loadKeyState()
			if err != nil {
				return err
			}
			return runRewrap(c.Context(), c.OutOrStdout(), s, to)
		},
	}
	cmd.Flags().StringVar(&to, "to", "", "keystore or passphrase (required)")
	_ = cmd.MarkFlagRequired("to")
	return cmd
}

const (
	bootstrapKEKKeystore   = bootstrap.KEKModeKeystore
	bootstrapKEKPassphrase = bootstrap.KEKModePassphrase
)

func runRewrap(ctx context.Context, out io.Writer, s *keyState, to string) error {
	current, err := currentKEK(s)
	if err != nil {
		return fmt.Errorf("keys rewrap: the current key cannot be loaded: %w", err)
	}

	switch {
	case to == bootstrapKEKKeystore && s.header.KEKType == "age-env" && s.loc == kek.IdentityInKeyring:
		return keepKeystore(out, s)
	case to == bootstrapKEKPassphrase && s.header.KEKType == "passphrase":
		fmt.Fprintln(out, "The vault key is already protected by a passphrase.")
		return nil
	}

	var next kek.KEK
	switch to {
	case bootstrapKEKKeystore:
		if s.identity.Store == nil {
			return NewUsageError("keys rewrap: no OS keyring is usable here; install a Secret Service provider or use --to passphrase")
		}
		if err := s.identity.Provision(false); err != nil {
			return fmt.Errorf("keys rewrap: store a new key in the OS keyring: %w", err)
		}
		next, err = s.identity.KEK(s.header.Salt)
	default:
		var pass []byte
		if pass, err = chooseVaultPassphrase(); err != nil {
			return err
		}
		next, err = kek.PassphraseKEK(pass, s.header.Salt, argon2.Recommended2026)
	}
	if err != nil {
		return fmt.Errorf("keys rewrap: derive the new key: %w", err)
	}

	if err := keyring.Rewrap(s.krPath, current, next); err != nil {
		if to == bootstrapKEKKeystore {
			_ = s.identity.RemoveKeyringItem()
		}
		return fmt.Errorf("keys rewrap: %w", err)
	}

	n, err := verifySecretsReadable(ctx, s.krPath, next)
	if err != nil {
		return fmt.Errorf("keys rewrap: the keyring now opens with the new key but %w; the old key material was kept", err)
	}

	if to == bootstrapKEKPassphrase {
		err = s.identity.Remove()
	} else {
		err = s.identity.RemovePlaintext()
	}
	if err != nil {
		return fmt.Errorf("keys rewrap: the vault is re-wrapped and verified but the old key could not be removed: %w", err)
	}
	fmt.Fprintf(out, "The vault key is now held in the %s. %d secret(s) verified; the plaintext identity was overwritten and removed.\n", to, n)
	return nil
}

// keepKeystore handles a key that is already in the keyring: the only thing
// left to clean up is a plaintext copy an older install left behind.
func keepKeystore(out io.Writer, s *keyState) error {
	if !s.onDisk {
		fmt.Fprintln(out, "The vault key is already held in the OS keyring.")
		return nil
	}
	removed, err := s.identity.MigrateToKeyring()
	if err != nil {
		return fmt.Errorf("keys rewrap: remove the plaintext copy: %w", err)
	}
	if removed {
		fmt.Fprintln(out, "The vault key was already in the OS keyring; the plaintext copy was overwritten and removed.")
	}
	return nil
}

// currentKEK loads the key-encryption key the keyring is wrapped under now.
func currentKEK(s *keyState) (kek.KEK, error) {
	switch s.header.KEKType {
	case "age-env":
		return s.identity.KEK(s.header.Salt)
	case "passphrase":
		pass, err := askVaultPassphrase()
		if err != nil {
			return nil, err
		}
		return kek.PassphraseKEK(pass, s.header.Salt, argon2.Recommended2026)
	}
	return file.LoadKeyringKEK(s.krPath)
}

// verifySecretsReadable reads every secret in the vault through the keyring
// opened with k and returns how many there were. The values are not kept.
func verifySecretsReadable(ctx context.Context, krPath string, k kek.KEK) (int, error) {
	kr, err := keyring.Open(krPath, k)
	if err != nil {
		return 0, fmt.Errorf("the keyring cannot be opened: %w", err)
	}
	defer kr.Zero()
	fb, err := file.OpenWithKeyring(file.Options{Dir: paths.Vault(llmcontext.DefaultLookup)}, kr)
	if err != nil {
		return 0, err
	}
	entries, err := fb.List(ctx, "")
	if err != nil {
		return 0, fmt.Errorf("the vault cannot be listed: %w", err)
	}
	var failed []string
	for _, e := range entries {
		value, _, err := fb.Get(ctx, e.Path)
		clear(value)
		if err != nil {
			failed = append(failed, e.Path)
		}
	}
	if len(failed) > 0 {
		return 0, fmt.Errorf("%d of %d secret(s) cannot be read (%s)", len(failed), len(entries), strings.Join(failed, ", "))
	}
	return len(entries), nil
}
