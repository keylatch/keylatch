package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/brokerd"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/paths"
	macospkg "github.com/keylatch/keylatch/packaging/macos"
)

// windowsHost is the machine the Windows installer acts on; tests replace it.
var windowsHost = brokerd.NewWindowsHost

// ownByBroker hands a path to the broker's service account.
func ownByBroker(path string) error {
	u, err := user.Lookup(paths.BrokerUser)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}

func installMac(ctx context.Context, out io.Writer) (brokerd.InstallResult, error) {
	in := &brokerd.MacInstaller{Root: "/", Files: macospkg.Files, Run: brokerd.ExecRunner{}, Euid: brokerEuid, Out: out, Own: ownByBroker}
	return in.Install(ctx)
}

func installWindows(ctx context.Context, out io.Writer) (brokerd.InstallResult, error) {
	in := &brokerd.WindowsInstaller{Host: windowsHost(), Run: brokerd.ExecRunner{}, Out: out}
	return in.Install(ctx)
}

func enrollWindows(_ context.Context, account, keyFile string) (string, error) {
	if keyFile == "" {
		return "", NewUsageError("on Windows the user exports the key first ('keylatch-presence.exe public-key > key.pem'); pass it with --key-file")
	}
	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}
	return brokerd.EnrollWindows(windowsHost(), brokerd.AdminDir(brokerd.DefaultStateRoot), account, pemBytes)
}

func newBrokerEnrollPresenceCmd() *cobra.Command {
	var account, keyFile string
	cmd := &cobra.Command{
		Use:   "enroll-presence",
		Short: "Register a user's presence key with the broker (needs root or an administrator)",
		Long: `Register the public key of a user's presence helper (Secure Enclave on macOS,
Windows Hello on Windows). Privileged broker requests then complete only when
the helper signs a challenge after Touch ID or Windows Hello.

Only root or an administrator can enroll, so a program running as the user
cannot register a key of its own and approve itself.

macOS: 'sudo keylatch broker enroll-presence --user <name>' asks the helper in
that user's session for its key. Windows: the user runs
'keylatch-presence.exe public-key > key.pem', then an elevated prompt runs
'keylatch broker enroll-presence --user <DOMAIN\name> --key-file key.pem'.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if account == "" {
				return NewUsageError("broker enroll-presence: --user is required")
			}
			var (
				where string
				err   error
			)
			switch runtime.GOOS {
			case "darwin":
				where, err = enrollMac(c.Context(), account, keyFile)
			case "windows":
				where, err = enrollWindows(c.Context(), account, keyFile)
			default:
				return NewUsageError("broker enroll-presence: Linux uses polkit; there is nothing to enroll")
			}
			if err != nil {
				if errors.Is(err, brokerd.ErrNotRoot) || errors.Is(err, brokerd.ErrNotAdmin) {
					return NewSecurityBlock("%v", err)
				}
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("broker enroll-presence: %w", err))
			}
			fmt.Fprintf(c.OutOrStdout(), "enrolled the presence key of %s: %s\n", account, where)
			return nil
		},
	}
	cmd.Flags().StringVar(&account, "user", "", "account whose presence key to enroll")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "PEM public key exported by the presence helper (default on macOS: ask the helper)")
	return cmd
}

func enrollMac(ctx context.Context, account, keyFile string) (string, error) {
	u, err := user.Lookup(account)
	if err != nil {
		return "", err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return "", err
	}
	if keyFile != "" {
		pemBytes, err := os.ReadFile(keyFile)
		if err != nil {
			return "", err
		}
		if brokerEuid() != 0 {
			return "", brokerd.ErrNotRoot
		}
		dk := brokerd.DirKeys{Dir: filepath.Join(brokerd.DefaultStateRoot, "presence")}
		return dk.Path(uint32(uid)), dk.Enroll(uint32(uid), pemBytes)
	}
	return brokerd.EnrollPresence(ctx, brokerd.ExecRunner{}, brokerEuid, brokerd.DefaultStateRoot, uint32(uid))
}
