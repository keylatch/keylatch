package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/brokerd"
	"github.com/keylatch/keylatch/internal/proc"
	"github.com/keylatch/keylatch/internal/version"
)

// newBrokerCmd runs the system broker. keylatchd.service starts it under the
// keylatch account with the device root in $CREDENTIALS_DIRECTORY and the
// socket passed by systemd.
func newBrokerCmd() *cobra.Command {
	var socket, stateRoot, binary string
	var service bool
	cmd := &cobra.Command{
		Use:   "broker",
		Short: "Run the system broker (started by keylatchd.service)",
		Long: `broker holds the key hierarchy, the secret store, the policy and the audit log
under its own OS user and answers keylatch clients on its socket (a named pipe
on Windows). It needs the device root the platform hands it (the systemd
credential on Linux, the System keychain on macOS, the CNG-sealed file on
Windows), so run it through the service manager, not from a shell.
'keylatch broker install' sets the service up.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !slices.Contains([]string{"linux", "darwin", "windows"}, runtime.GOOS) {
				return fmt.Errorf("keylatchd: the system broker runs on Linux, macOS and Windows only")
			}
			if binary == "" {
				resolved, err := siblingKeylatch()
				if err != nil {
					return err
				}
				binary = resolved
			}
			opts := brokerd.Options{
				Version:     version.Version,
				StateRoot:   stateRoot,
				Socket:      socket,
				Binary:      binary,
				Env:         os.Getenv,
				PID:         os.Getpid(),
				Harden:      proc.Harden,
				Unsetenv:    os.Unsetenv,
				RequireLock: true,
				Out:         cmd.OutOrStdout(),
			}
			if service || brokerd.IsWindowsService() {
				return brokerd.RunService(brokerd.WindowsServiceName, func(ctx context.Context) error { return brokerd.Run(ctx, opts) })
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			return brokerd.Run(ctx, opts)
		},
	}
	cmd.Flags().BoolVar(&service, "service", false, "run under the Windows service control manager")
	cmd.Flags().StringVar(&socket, "socket", brokerd.DefaultSocket, "broker socket path when systemd does not pass one")
	cmd.Flags().StringVar(&stateRoot, "state", brokerd.DefaultStateRoot, "state directory")
	cmd.Flags().StringVar(&binary, "keylatch-bin", "", "keylatch executable the daemon runs for served verbs (default: next to keylatchd)")
	return cmd
}
