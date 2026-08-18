// Package cli — sandbox subcommand tree.
package cli

import (
	"encoding/json"
	"fmt"
	goos "runtime"

	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/spf13/cobra"
)

// newSandboxCmd returns the `sandbox` subcommand group.
func newSandboxCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Manage the keylatch sandbox environment",
		Long: `Manage the keylatch direct_classic_sandboxed runtime mode.

The sandbox provides a credential-isolated execution context using bwrap (Linux)
or sandbox-exec (macOS). Use 'sandbox doctor' to diagnose availability.

'sandbox run' is [experimental] and not yet implemented — it prints usage
guidance pointing at 'keylatch run --runtime direct_classic_sandboxed', the
working equivalent, instead of executing anything.`,
	}
	cmd.AddCommand(newSandboxDoctorCmd())
	cmd.AddCommand(newSandboxRunCmd())
	return cmd
}

// sandboxDoctorOutput is the JSON shape for `sandbox doctor`.
type sandboxDoctorOutput struct {
	Platform  string `json:"platform"`
	Available bool   `json:"available"`
	Tool      string `json:"tool,omitempty"`
	Path      string `json:"path,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// newSandboxDoctorCmd returns the `sandbox doctor` subcommand.
func newSandboxDoctorCmd() *cobra.Command {
	var useJSON bool
	cmd := &cobra.Command{
		Use:   "doctor [connection]",
		Short: "Diagnose sandbox availability for a connection",
		Long: `Check whether the sandbox runtime is available on this system.

On Linux: reports whether bwrap (bubblewrap) is installed and its path.
On macOS: reports that sandbox-exec is available (built-in).
On Windows: reports that sandboxed execution is not supported.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			platform := goos.GOOS
			out := buildSandboxDoctorOutput(platform)

			if len(args) > 0 {
				// Future: resolve connection and check profile exists.
				// For now, append the connection slug to the output as context.
				out.Reason = fmt.Sprintf("connection=%s: %s", args[0], out.Reason)
			}

			if useJSON {
				b, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(c.OutOrStdout(), string(b))
				return nil
			}

			status := "available"
			if !out.Available {
				status = "not available"
			}
			fmt.Fprintf(c.OutOrStdout(), "sandbox doctor — platform: %s — %s\n", platform, status)
			if out.Tool != "" {
				fmt.Fprintf(c.OutOrStdout(), "  tool: %s\n", out.Tool)
			}
			if out.Path != "" {
				fmt.Fprintf(c.OutOrStdout(), "  path: %s\n", out.Path)
			}
			if out.Reason != "" {
				fmt.Fprintf(c.OutOrStdout(), "  reason: %s\n", out.Reason)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&useJSON, "json", false, "output as JSON")
	return cmd
}

// buildSandboxDoctorOutput constructs the doctor report for the given platform.
func buildSandboxDoctorOutput(platform string) sandboxDoctorOutput {
	switch platform {
	case "windows":
		return sandboxDoctorOutput{
			Platform:  platform,
			Available: false,
			Reason:    "Windows sandbox not supported in 1.0.0",
		}
	case "linux":
		if path, ok := sandbox.DetectBwrap(); ok {
			return sandboxDoctorOutput{
				Platform:  platform,
				Available: true,
				Tool:      "bwrap",
				Path:      path,
				Reason:    "bwrap found — direct_classic_sandboxed mode available",
			}
		}
		return sandboxDoctorOutput{
			Platform:  platform,
			Available: false,
			Tool:      "bwrap",
			Reason:    "bwrap not found — install bubblewrap: apt-get install bubblewrap | dnf install bubblewrap | pacman -S bubblewrap",
		}
	default:
		// macOS and other POSIX: sandbox-exec is built-in.
		return sandboxDoctorOutput{
			Platform:  platform,
			Available: true,
			Tool:      "sandbox-exec",
			Reason:    "sandbox-exec built-in — direct_classic_sandboxed mode available",
		}
	}
}

// newSandboxRunCmd returns the `sandbox run` subcommand.
func newSandboxRunCmd() *cobra.Command {
	var connection string
	cmd := &cobra.Command{
		Use:   "run [--connection <slug>] -- <command> [args...]",
		Short: "[experimental] Run a command inside the keylatch sandbox (not yet implemented)",
		Long: `[EXPERIMENTAL — not yet implemented]

This command is wired into the CLI but does not yet execute anything: it
always exits with usage guidance pointing at the working equivalent,
'keylatch run --runtime direct_classic_sandboxed'. Kept here to reserve the
UX shape for a future release; do not script against it.

The sandbox isolates the subprocess using bwrap (Linux) or sandbox-exec (macOS).
Credentials are injected via environment variables inside the sandbox; the host
environment is never exposed to the subprocess.

The connection slug identifies which sandbox profile and credentials to use.
The command and arguments are passed after the -- separator.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			platform := goos.GOOS

			// Windows is unsupported.
			if platform == "windows" {
				return NewUsageError("sandbox run: not supported on Windows — use 'direct_classic' or 'gateway_typed' instead")
			}

			// On Linux, verify bwrap is available.
			if platform == "linux" {
				if _, ok := sandbox.DetectBwrap(); !ok {
					return NewUsageError("sandbox run: bwrap not found.\n%s", sandbox.BwrapInstallHint)
				}
			}

			if connection == "" {
				return NewUsageError("sandbox run: --connection is required")
			}

			return NewUsageError("sandbox run: [experimental] not yet implemented — use the working equivalent instead:\n  keylatch run --runtime direct_classic_sandboxed %s -- %s",
				connection, args[0])
		},
	}
	cmd.Flags().StringVar(&connection, "connection", "", "connection slug for sandbox profile lookup")
	return cmd
}
