package cli

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// approverKDFParams derive the approver key from its passphrase. Replaced in
// tests to keep them fast.
var approverKDFParams = argon2.Recommended2026

func approverKeyPath(env llmcontext.Lookup) string {
	return filepath.Join(paths.ConfigDir(env), "approver.json")
}

// requireHumanApprover enforces the conditions every approval decision
// shares: no detected agent session and an interactive terminal.
func requireHumanApprover(command, sessionCode, ttyCode string) error {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return NewSecurityBlock("%s: command is not permitted inside an LLM session. Approval decisions must be made by a human operator outside of an LLM session. (%s)", command, sessionCode)
	}
	return requireInteractiveTerminal(command, ttyCode)
}

// unlockApprover asks for the approver passphrase on the terminal and
// returns the approver signing key. The passphrase is never read from a
// flag, a file or the environment, so a process without the human's
// terminal cannot supply it.
func unlockApprover(command, missingCode, wrongCode string) (ed25519.PrivateKey, error) {
	key, err := approval.LoadApproverKey(approverKeyPath(llmcontext.DefaultLookup))
	if errors.Is(err, approval.ErrNoApproverKey) {
		return nil, &CLIError{
			Class:   "UserError",
			Code:    exitcode.UserError,
			Message: fmt.Sprintf("%s: no approver passphrase is set. Run 'keylatch approve init' in a terminal to set one. (%s)", command, missingCode),
		}
	}
	if err != nil {
		return nil, NewSecurityBlock("%s: cannot read the approver key: %v. Run 'keylatch approve init' to replace it. (%s)", command, err, missingCode)
	}
	pass, err := promptHidden("Approver passphrase")
	if err != nil {
		return nil, NewSecurityBlock("%s: reading the approver passphrase: %v (%s)", command, err, wrongCode)
	}
	defer clear(pass)
	priv, err := key.Unlock(pass)
	if err != nil {
		return nil, NewSecurityBlock("%s: %v (%s)", command, err, wrongCode)
	}
	return priv, nil
}

// printApprovalSummary shows the human what they are about to decide.
// Every field but the token is written by the requester, so control and
// format characters are removed before display.
func printApprovalSummary(w io.Writer, ar *approval.ApprovalRequest) {
	fmt.Fprintf(w, "Request %s\n", ar.Token)
	fmt.Fprintf(w, "  actor:         %s\n", displaySafe(ar.Actor))
	fmt.Fprintf(w, "  connection:    %s\n", displaySafe(ar.Connection))
	fmt.Fprintf(w, "  capability:    %s\n", displaySafe(ar.Capability))
	fmt.Fprintf(w, "  request hash:  %s\n", displaySafe(ar.RequestHash))
	if ar.Note != "" {
		fmt.Fprintf(w, "  note:          %s\n", displaySafe(ar.Note))
	}
	fmt.Fprintf(w, "  requested:     %s\n", ar.CreatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "  expires:       %s\n", ar.ExpiresAt.UTC().Format(time.RFC3339))
}

// displaySafe drops control and format characters (escape sequences,
// carriage returns, bidi overrides) that could rewrite what the terminal
// shows.
func displaySafe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

func newApproveInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Set or change the approver passphrase",
		Long: `Set or change the approver passphrase.

Every approval and denial is signed with a key derived from this
passphrase, and approvals that are not signed with it are rejected. The
passphrase is only ever read from an interactive terminal; keep it out of
any file, environment variable or script an agent can reach.

Changing the passphrase asks for the current one first. Decisions signed
with the old passphrase stop verifying.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := requireHumanApprover("approve init", "KL-4101", "KL-4105"); err != nil {
				return err
			}
			path := approverKeyPath(llmcontext.DefaultLookup)
			existing, err := approval.LoadApproverKey(path)
			switch {
			case err == nil:
				pass, err := promptHidden("Current approver passphrase")
				if err != nil {
					return NewSecurityBlock("approve init: reading the passphrase: %v (KL-4107)", err)
				}
				priv, err := existing.Unlock(pass)
				clear(pass)
				if err != nil {
					return NewSecurityBlock("approve init: %v (KL-4107)", err)
				}
				clear(priv)
			case !errors.Is(err, approval.ErrNoApproverKey):
				return NewSecurityBlock("approve init: cannot read the approver key at %s: %v. Move the file aside to start over. (KL-4108)", path, err)
			}

			pass, err := promptHidden("New approver passphrase")
			if err != nil {
				return NewSecurityBlock("approve init: reading the passphrase: %v (KL-4108)", err)
			}
			defer clear(pass)
			confirm, err := promptHidden("Repeat approver passphrase")
			if err != nil {
				return NewSecurityBlock("approve init: reading the passphrase: %v (KL-4108)", err)
			}
			defer clear(confirm)
			if subtle.ConstantTimeCompare(pass, confirm) != 1 {
				return &CLIError{Class: "UserError", Code: exitcode.UserError, Message: "approve init: the passphrases do not match. (KL-4108)"}
			}
			key, priv, err := approval.NewApproverKey(pass, approverKDFParams)
			if err != nil {
				return &CLIError{Class: "UserError", Code: exitcode.UserError, Message: fmt.Sprintf("approve init: %v (KL-4108)", err)}
			}
			clear(priv)
			if err := approval.SaveApproverKey(path, key); err != nil {
				return &CLIError{Class: "OperationFailed", Code: exitcode.OperationFailed, Message: fmt.Sprintf("approve init: %v (KL-4108)", err)}
			}
			fmt.Fprintf(c.OutOrStdout(), "approver passphrase set (%s)\n", path)
			return nil
		},
	}
}
