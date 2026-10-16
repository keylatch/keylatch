package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
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
	cmd := &cobra.Command{
		Use:   "broker",
		Short: "Run the system broker (started by keylatchd.service)",
		Long: `broker holds the key hierarchy, the secret store, the policy and the audit log
under its own OS user and answers keylatch clients on /run/keylatch/broker.sock.
It needs the device root credential systemd hands to keylatchd.service, so run
it through the unit, not from a shell. 'sudo keylatch broker install' sets the
unit up.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if runtime.GOOS != "linux" {
				return fmt.Errorf("keylatchd: the system broker runs on Linux only")
			}
			if binary == "" {
				resolved, err := siblingKeylatch()
				if err != nil {
					return err
				}
				binary = resolved
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			return brokerd.Run(ctx, brokerd.Options{
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
			})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", brokerd.DefaultSocket, "broker socket path when systemd does not pass one")
	cmd.Flags().StringVar(&stateRoot, "state", brokerd.DefaultStateRoot, "state directory")
	cmd.Flags().StringVar(&binary, "keylatch-bin", "", "keylatch executable the daemon runs for served verbs (default: next to keylatchd)")
	return cmd
}
