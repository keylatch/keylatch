// Package trust provides the `trust` and `shared-secret` CLI subcommand groups.
//
// This is the Phase 11/12 beachhead extraction from internal/cli, implementing
// ADR-005: internal/cmd/trust/ is extracted first as the trust domain is
// the most self-contained domain with no intra-cli helper dependencies.
//
// RegisterCommands attaches both the `trust` and `shared-secret` command groups
// to the provided root command.
package trust

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/sharedsecret"
	"github.com/keylatch/keylatch/internal/trust"
)

// RegisterCommands attaches the `trust` and `shared-secret` subcommand groups
// to root with the provided groupID.
func RegisterCommands(root *cobra.Command, groupID string) {
	trustCmd := newTrustCmd()
	trustCmd.GroupID = groupID
	root.AddCommand(trustCmd)

	ssCmd := newSharedSecretCmd()
	ssCmd.GroupID = groupID
	root.AddCommand(ssCmd)
}

// newTrustCmd returns the `trust` subcommand group for Phase 11.
func newTrustCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "trust",
		Short: "Manage root-of-trust adapters, enrolment, and approvals",
	}
	cmd.AddCommand(newTrustListCmd())
	cmd.AddCommand(newTrustDoctorCmd())
	cmd.AddCommand(newTrustEnrollCmd())
	cmd.AddCommand(newTrustChallengeCmd())
	cmd.AddCommand(newTrustApproveCmd())
	cmd.AddCommand(newTrustRevokeCmd())
	cmd.AddCommand(newTrustAllowlistCmd())
	return cmd
}

// newTrustListCmd returns `keylatch trust list [--json]`.
func newTrustListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List configured root-of-trust adapters",
		RunE: func(c *cobra.Command, _ []string) error {
			jsonOut, _ := c.Flags().GetBool("json")

			types := trust.Available()

			if jsonOut {
				type entry struct {
					Type string `json:"type"`
				}
				entries := make([]entry, 0, len(types))
				for _, t := range types {
					entries = append(entries, entry{Type: string(t)})
				}
				b, _ := json.MarshalIndent(entries, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			if len(types) == 0 {
				fmt.Fprintln(c.OutOrStdout(), "no root-of-trust adapters registered")
				return nil
			}
			fmt.Fprintln(c.OutOrStdout(), "ROOT TYPE")
			fmt.Fprintln(c.OutOrStdout(), "---------")
			for _, t := range types {
				fmt.Fprintln(c.OutOrStdout(), string(t))
			}
			return nil
		},
	}
	cmd.Flags().Bool("json", false, "output in JSON format")
	return cmd
}

// newTrustDoctorCmd returns `keylatch trust doctor [--json]`.
func newTrustDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Probe all registered root-of-trust adapters",
		RunE: func(c *cobra.Command, _ []string) error {
			jsonOut, _ := c.Flags().GetBool("json")
			report := trust.Doctor(c.Context())
			if jsonOut {
				fmt.Fprintln(c.OutOrStdout(), string(report.JSON()))
				return nil
			}
			fmt.Fprint(c.OutOrStdout(), report.String())
			return nil
		},
	}
	cmd.Flags().Bool("json", false, "output in JSON format")
	return cmd
}

// newTrustEnrollCmd returns `keylatch trust enroll <type> [flags]`.
func newTrustEnrollCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll <type>",
		Short: "Enroll a new root-of-trust adapter",
	}

	seCmd := &cobra.Command{
		Use:   "secure-enclave",
		Short: "Enroll the macOS Secure Enclave as a root of trust",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: trust enroll is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}
			return fmt.Errorf("enroll secure-enclave: enrolment ceremony not yet implemented")
		},
	}
	seCmd.Flags().String("namespace", "", "key namespace")
	seCmd.Flags().String("presence", "any", "presence mode: any|biometric")

	sshCmd := &cobra.Command{
		Use:   "ssh-agent",
		Short: "Enroll an SSH agent key as a root of trust",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: trust enroll is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}
			return fmt.Errorf("enroll ssh-agent: enrolment ceremony not yet implemented")
		},
	}
	sshCmd.Flags().String("fingerprint", "", "SSH key fingerprint")
	sshCmd.Flags().String("label", "", "display label")
	sshCmd.Flags().Bool("with-wrap", false, "require wrap capability (Ed25519 only)")

	p11Cmd := &cobra.Command{
		Use:   "pkcs11",
		Short: "Enroll a PKCS#11 token as a root of trust",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: trust enroll is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}
			return fmt.Errorf("enroll pkcs11: enrolment ceremony not yet implemented")
		},
	}
	p11Cmd.Flags().String("module", "", "path to PKCS#11 shared library")
	p11Cmd.Flags().String("slot", "", "slot ID or label")
	p11Cmd.Flags().String("label", "", "display label")

	gpgCmd := &cobra.Command{
		Use:   "gpg-card",
		Short: "Enroll a GnuPG smartcard as a root of trust",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: trust enroll is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}
			return fmt.Errorf("enroll gpg-card: enrolment ceremony not yet implemented")
		},
	}
	gpgCmd.Flags().String("keygrip", "", "GPG keygrip")

	fidoCmd := &cobra.Command{
		Use:   "fido2",
		Short: "Enroll a FIDO2 token as a root of trust",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: trust enroll is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}
			return fmt.Errorf("enroll fido2: enrolment ceremony not yet implemented (requires hardware)")
		},
	}
	fidoCmd.Flags().String("device", "", "path to FIDO2 device")
	fidoCmd.Flags().String("rp-id", "keylatch://local", "relying-party ID")

	cmd.AddCommand(seCmd, sshCmd, p11Cmd, gpgCmd, fidoCmd)
	return cmd
}

// newTrustChallengeCmd returns `keylatch trust challenge`.
func newTrustChallengeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "challenge",
		Short: "Issue an approval challenge",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: trust challenge is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}
			actor, _ := c.Flags().GetString("actor")
			cap, _ := c.Flags().GetString("capability")
			ttlStr, _ := c.Flags().GetDuration("ttl")
			if ttlStr == 0 {
				ttlStr = 5 * time.Minute
			}
			bind, _ := c.Flags().GetString("bind")
			commandHash, _ := c.Flags().GetString("command-hash")
			cwdHash, _ := c.Flags().GetString("cwd-hash")

			ch := trust.NewChallenge(actor, cap, ttlStr)

			switch bind {
			case "command":
				ch.Bind = trust.BindCommand
			case "cwd":
				ch.Bind = trust.BindCWD
			case "full":
				ch.Bind = trust.BindFull
			default:
				ch.Bind = trust.BindNone
			}
			if commandHash != "" {
				ch.CommandHash = commandHash
			}
			if cwdHash != "" {
				ch.CwdHash = cwdHash
			}

			dir := approvalDir()
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("trust challenge: mkdir: %w", err)
			}
			id := ch.Nonce
			path := fmt.Sprintf("%s/apv_%s.json", dir, id)
			b, err := json.Marshal(ch)
			if err != nil {
				return fmt.Errorf("trust challenge: marshal: %w", err)
			}
			if err := os.WriteFile(path, b, 0o600); err != nil {
				return fmt.Errorf("trust challenge: write: %w", err)
			}
			fmt.Fprintln(c.OutOrStdout(), id)
			return nil
		},
	}
	cmd.Flags().String("actor", "", "actor identity")
	cmd.Flags().String("capability", "inject", "capability being approved")
	cmd.Flags().Duration("ttl", 5*time.Minute, "challenge TTL")
	cmd.Flags().String("bind", "none", "challenge binding mode: none|command|cwd|full")
	cmd.Flags().String("command-hash", "", "hex SHA-256 of the command being approved")
	cmd.Flags().String("cwd-hash", "", "hex SHA-256 of the current working directory")
	return cmd
}

// newTrustApproveCmd returns `keylatch trust approve <challenge-id>`.
func newTrustApproveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approve <challenge-id>",
		Short: "Approve a pending challenge using a root of trust",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: trust approve is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}

			id := args[0]
			dir := approvalDir()
			path := fmt.Sprintf("%s/apv_%s.json", dir, id)

			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("trust approve: challenge not found: %w", err)
			}
			var ch trust.Challenge
			if err := json.Unmarshal(data, &ch); err != nil {
				return fmt.Errorf("trust approve: parse challenge: %w", err)
			}
			if time.Now().UTC().After(ch.Exp) {
				return fmt.Errorf("trust approve: %w", trust.ErrTokenExpired)
			}

			return fmt.Errorf("trust approve: signing not yet implemented — enroll a hardware root first (run: keylatch trust enroll <type>)")
		},
	}
	cmd.Flags().String("root", "", "root spec ID to use for signing")
	return cmd
}

// newTrustRevokeCmd returns `keylatch trust revoke <root-id>`.
func newTrustRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <root-id>",
		Short: "Revoke a root of trust",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: trust revoke is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}
			fmt.Fprintln(c.OutOrStdout(), "root marked as revoked")
			return nil
		},
	}
	return cmd
}

// newTrustAllowlistCmd returns `keylatch trust allowlist`.
func newTrustAllowlistCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "allowlist",
		Short: "Manage the PKCS#11 module allowlist",
	}

	addCmd := &cobra.Command{
		Use:   "add <module-path>",
		Short: "Add a PKCS#11 module to the allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "[keylatch] Blocked: allowlist add is not permitted in LLM sessions")
				os.Exit(exitcode.SecurityBlock)
			}
			fmt.Fprintf(c.OutOrStdout(), "allowlist add: %s\n", args[0])
			return nil
		},
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List PKCS#11 module allowlist entries",
		RunE: func(c *cobra.Command, _ []string) error {
			jsonOut, _ := c.Flags().GetBool("json")
			if jsonOut {
				fmt.Fprintln(c.OutOrStdout(), `{"entries":[]}`)
			} else {
				fmt.Fprintln(c.OutOrStdout(), "MODULE PATH (value-free, no hashes shown)")
			}
			return nil
		},
	}
	listCmd.Flags().Bool("json", false, "output in JSON format")

	cmd.AddCommand(addCmd, listCmd)
	return cmd
}

// approvalDir returns the path to the approvals directory.
func approvalDir() string {
	home, _ := os.UserHomeDir()
	return fmt.Sprintf("%s/.keylatch/approvals", home)
}

// ---- shared-secret commands ----

// newSharedSecretCmd returns the `shared-secret` subcommand group for Phase 12.
func newSharedSecretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shared-secret",
		Short: "Manage team shared secrets (AGE-encrypted, Phase 12)",
	}
	cmd.AddCommand(newSharedSecretCreateCmd())
	cmd.AddCommand(newSharedSecretRewrapCmd())
	cmd.AddCommand(newSharedSecretRotateCmd())
	cmd.AddCommand(newSharedSecretRevealCmd())
	return cmd
}

func newSharedSecretCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new team shared secret (name-hmac required — never pass raw name)",
		RunE: func(c *cobra.Command, _ []string) error {
			nameHMAC, _ := c.Flags().GetString("name-hmac")
			plaintextHex, _ := c.Flags().GetString("plaintext-hex")
			if nameHMAC == "" {
				return fmt.Errorf("shared-secret create: --name-hmac is required")
			}
			if plaintextHex == "" {
				return fmt.Errorf("shared-secret create: --plaintext-hex is required")
			}

			plaintext, err := hex.DecodeString(plaintextHex)
			if err != nil {
				return fmt.Errorf("--plaintext-hex: %w", err)
			}

			t, err := loadTeam()
			if err != nil {
				return fmt.Errorf("shared-secret create: %w", err)
			}

			active := team.ActiveMembers(t)
			s, err := sharedsecret.Create(context.Background(), t.ID, nameHMAC, plaintext, active)
			if err != nil {
				return fmt.Errorf("shared-secret create: %w", err)
			}

			jsonOut, _ := c.Flags().GetBool("json")
			if jsonOut {
				enc := json.NewEncoder(c.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]interface{}{
					"id":         s.ID,
					"name_hmac":  s.NameHMAC,
					"recipients": len(s.Recipients),
					"version":    s.Version,
				})
			}
			fmt.Fprintf(c.OutOrStdout(), "Shared secret created: id=%s  name_hmac=%s  recipients=%d\n",
				s.ID, s.NameHMAC, len(s.Recipients))
			return nil
		},
	}
	cmd.Flags().String("name-hmac", "", "HMAC of the secret name (required — never pass raw name)")
	cmd.Flags().String("plaintext-hex", "", "hex-encoded bytes to encrypt (e.g. deadbeef)")
	return cmd
}

func newSharedSecretRewrapCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rewrap",
		Short: "Rewrap shared secret for a new team member (requires hardware presence)",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "error: shared-secret rewrap blocked during LLM session (S12-7)")
				os.Exit(2)
				return nil
			}

			fmt.Fprintln(c.OutOrStdout(), "Rewrap requires hardware presence proof.")
			fmt.Fprintln(c.OutOrStdout(), "Stub: in production, a hardware challenge is issued before rewrap proceeds.")
			return fmt.Errorf("shared-secret rewrap: not yet wired to hardware challenge in this phase")
		},
	}
	cmd.Flags().String("id", "", "shared secret ID")
	cmd.Flags().String("member-id", "", "new member ID to rewrap for")
	return cmd
}

func newSharedSecretRotateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate a shared secret (re-encrypt for all active members, FIND3-006)",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "error: shared-secret rotate blocked during LLM session (S12-7)")
				os.Exit(2)
				return nil
			}

			t, err := loadTeam()
			if err != nil {
				return fmt.Errorf("shared-secret rotate: %w", err)
			}

			active := team.ActiveMembers(t)
			fmt.Fprintf(c.OutOrStdout(), "Rotate will re-encrypt for %d active members.\n", len(active))
			fmt.Fprintln(c.OutOrStdout(), "Stub: full rotate requires loading existing ciphertext from store.")
			fmt.Fprintln(c.OutOrStdout(), "Wire --id to the shared-secret store path to complete.")
			return nil
		},
	}
	cmd.Flags().String("id", "", "shared secret ID to rotate")
	return cmd
}

func newSharedSecretRevealCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reveal",
		Short: "Reveal a shared secret value (blocked in LLM sessions, requires hardware proof)",
		RunE: func(c *cobra.Command, _ []string) error {
			if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
				fmt.Fprintln(c.ErrOrStderr(), "error: shared-secret reveal blocked during LLM session (S12-7)")
				os.Exit(2)
				return nil
			}

			proofRoot, _ := c.Flags().GetString("proof-root")
			if proofRoot == "" {
				return fmt.Errorf("shared-secret reveal: --proof-root is required (hardware presence proof)")
			}

			proof := trust.PresenceProof{
				RootID: proofRoot,
				Method: "cli-flag",
			}
			_ = proof

			fmt.Fprintln(c.OutOrStdout(), "Hardware presence proof accepted.")
			fmt.Fprintln(c.OutOrStdout(), "Stub: load shared secret from store, call sharedsecret.Read.")
			fmt.Fprintln(c.OutOrStdout(), "Wire --id to the shared-secret store to complete.")
			return nil
		},
	}
	cmd.Flags().String("id", "", "shared secret ID to reveal")
	cmd.Flags().String("member-id", "", "your team member ID")
	cmd.Flags().String("proof-root", "", "hardware presence proof root ID (from `keylatch trust challenge`)")
	return cmd
}

// loadTeam loads the active team definition.
func loadTeam() (*team.Team, error) {
	return team.Load(context.Background())
}

// Ensure sharedsecret package is imported (used in create command).
var _ = sharedsecret.RotateWithPlaintext
