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
or sandbox-exec (macOS). Use 'sandbox doctor' to diagnose availability.`,
	}
	cmd.AddCommand(newSandboxDoctorCmd())
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
