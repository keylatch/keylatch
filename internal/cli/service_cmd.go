package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/runner"
)

var serviceConnName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// systemCredstore and userCredstore are where systemd looks for encrypted
// credentials, system-wide and per user.
const (
	systemCredstore = "/etc/credstore.encrypted"
	userCredstore   = ".config/credstore.encrypted"
)

func credentialPath(scope, connection string) (string, error) {
	file := runner.ServiceCredentialName(connection) + ".cred"
	if scope != "user" {
		return filepath.Join(systemCredstore, file), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, userCredstore, file), nil
}

// sealCredential seals capability into the unit's credential file with
// systemd-creds. The capability travels on standard input, never in argv. The
// system store is root's, so that scope runs through sudo unless already root.
// Tests replace it.
var sealCredential = func(ctx context.Context, scope, connection, dest string, capability []byte) error {
	bin := ""
	for _, p := range []string{"/usr/bin/systemd-creds", "/bin/systemd-creds"} {
		if _, err := os.Stat(p); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		return errors.New("systemd-creds was not found; systemd 250 or newer is required")
	}
	name := "--name=" + runner.ServiceCredentialName(connection)
	var cmd *exec.Cmd
	switch {
	case scope == "user":
		if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
			return err
		}
		cmd = exec.CommandContext(ctx, bin, "--user", "encrypt", name, "-", dest) //nolint:gosec // fixed binary; arguments built here
	case os.Geteuid() == 0:
		cmd = exec.CommandContext(ctx, bin, "encrypt", "--with-key=auto", name, "-", dest) //nolint:gosec // fixed binary; arguments built here
	default:
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			return fmt.Errorf("writing %s needs root and sudo was not found", dest)
		}
		cmd = exec.CommandContext(ctx, sudo, bin, "encrypt", "--with-key=auto", name, "-", dest) //nolint:gosec // fixed binaries; arguments built here
	}
	cmd.Stdin = bytes.NewReader(capability)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	return cmd.Run()
}

func requireHumanService(what string) error {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return NewSecurityBlock("keylatch service %s changes which units receive a credential and needs a human. Ask the person at the machine to run it in a terminal.", what)
	}
	return nil
}

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Give systemd units their credentials through the broker",
		Long: `Enroll systemd service units so that each receives a connection from the system
broker and nothing else does. Enrollment records, per unit, a digest of the unit
file and its drop-ins, ExecStart, and whether a transient unit is allowed, and
seals a random capability into the unit's credential file with systemd-creds.
The sealed file holds only that capability, never the secret: it proves nothing
outside the enrolled unit, which the broker identifies by its control group and
re-inspects on every release. Inside the unit, run
'keylatch run <connection> --runtime service -- <command>'.`,
	}
	cmd.AddCommand(newServiceEnrollCmd(), newServiceRevokeCmd(), newServiceListCmd(), newServiceRenderCmd())
	return cmd
}

func serviceBroker(c *cobra.Command) (brokerCaller, error) {
	return brokerClient(llmcontext.DefaultLookup)
}

func newServiceEnrollCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll <connection> --unit <unit>...",
		Short: "Let units receive a connection (needs your presence)",
		Long: `Enroll the named units for a connection. The broker reads each unit's state from
the service manager, shows you what it is about to allow and asks for your
presence. Enrolling again replaces the connection's previous enrollment and
capability, so list every unit that should keep receiving it.

--scope system (the default, recommended) seals the capability into
/etc/credstore.encrypted and needs root for that one write (sudo is asked).
--scope user seals it into ~/.config/credstore.encrypted; the unit files of a
user manager are writable by that user, so they are pinned by digest and the
capability is useless outside the unit.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := requireHumanService("enroll"); err != nil {
				return err
			}
			conn := args[0]
			if !serviceConnName.MatchString(conn) {
				return NewUsageError("service enroll: %q is not a connection name a unit credential can carry", conn)
			}
			units, _ := c.Flags().GetStringArray("unit")
			scope, _ := c.Flags().GetString("scope")
			transient, _ := c.Flags().GetBool("allow-transient")
			if len(units) == 0 {
				return NewUsageError("service enroll: at least one --unit is required")
			}
			if scope != "system" && scope != "user" {
				return NewUsageError("service enroll: --scope must be system or user")
			}
			dest, err := credentialPath(scope, conn)
			if err != nil {
				return withExitCode(exitcode.OperationFailed, err)
			}
			bc, err := serviceBroker(c)
			if err != nil {
				return err
			}
			resp, err := brokerPrivileged(bc, "service enroll", brokerapi.Request{Op: brokerapi.OpServiceEnroll, Service: &brokerapi.ServiceRequest{
				Connection: conn, Units: units, Scope: scope, AllowTransient: transient,
			}})
			if err != nil {
				return err
			}
			capability := resp.Service.Capability
			defer clear(capability)
			if err := sealCredential(c.Context(), scope, conn, dest, capability); err != nil {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("service enroll: seal the credential: %w", err))
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "enrolled %s for %s (%s scope); credential file %s\n", strings.Join(units, ", "), conn, scope, dest)
			fmt.Fprintf(out, "add to each unit:\n%s\n", strings.Join(unitLines(conn, dest), "\n"))
			return nil
		},
	}
	cmd.Flags().StringArray("unit", nil, "service unit that may receive the connection (repeatable)")
	cmd.Flags().String("scope", "system", "service manager the units belong to: system or user")
	cmd.Flags().Bool("allow-transient", false, "also accept units created with systemd-run, which have no unit file")
	return cmd
}

func newServiceRevokeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "revoke <connection>",
		Short: "Stop units receiving a connection (needs your presence)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := requireHumanService("revoke"); err != nil {
				return err
			}
			unit, _ := c.Flags().GetString("unit")
			bc, err := serviceBroker(c)
			if err != nil {
				return err
			}
			if _, err := brokerPrivileged(bc, "service revoke", brokerapi.Request{Op: brokerapi.OpServiceRevoke, Service: &brokerapi.ServiceRequest{Connection: args[0], Unit: unit}}); err != nil {
				return err
			}
			if unit == "" {
				fmt.Fprintf(c.OutOrStdout(), "revoked every unit of %s; delete its credential file when no unit loads it\n", args[0])
			} else {
				fmt.Fprintf(c.OutOrStdout(), "revoked %s for %s\n", unit, args[0])
			}
			return nil
		},
	}
	cmd.Flags().String("unit", "", "revoke this unit only (default: every unit of the connection)")
	return cmd
}

func listServices(c *cobra.Command) ([]brokerapi.ServiceInfo, error) {
	bc, err := serviceBroker(c)
	if err != nil {
		return nil, err
	}
	resp, err := bc.Call(brokerapi.Request{Op: brokerapi.OpServiceList, Service: &brokerapi.ServiceRequest{}})
	if err != nil {
		return nil, withExitCodeOperation("service list", err)
	}
	if !resp.OK || resp.Service == nil {
		return nil, brokerFailure("service list", resp)
	}
	return resp.Service.Services, nil
}

func newServiceListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List enrolled units and whether they still match their enrollment",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			services, err := listServices(c)
			if err != nil {
				return err
			}
			if services == nil {
				services = []brokerapi.ServiceInfo{}
			}
			if asJSON, _ := c.Flags().GetBool("json"); asJSON {
				return writeIndentedJSON(c.OutOrStdout(), map[string]any{"services": services})
			}
			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			for _, s := range services {
				state := "ok"
				if s.Changed {
					state = "CHANGED: " + s.Detail
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Connection, s.Unit, s.Scope, state)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().Bool("json", false, "print JSON")
	return cmd
}

func unitLines(connection, path string) []string {
	return []string{
		"LoadCredentialEncrypted=" + runner.ServiceCredentialName(connection) + ":" + path,
		"Environment=KEYLATCH_SERVICE_CONNECTION=" + connection,
	}
}

func newServiceRenderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "render-unit-lines <connection>",
		Short: "Print the unit lines that load a connection's credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			conn := args[0]
			if !serviceConnName.MatchString(conn) {
				return NewUsageError("service render-unit-lines: %q is not a connection name a unit credential can carry", conn)
			}
			format, _ := c.Flags().GetString("format")
			scope, _ := c.Flags().GetString("scope")
			if scope == "" {
				scope = "system"
				if brokerInstalled(llmcontext.DefaultLookup) {
					if services, err := listServices(c); err == nil {
						for _, s := range services {
							if s.Connection == conn {
								scope = s.Scope
							}
						}
					}
				}
			}
			dest, err := credentialPath(scope, conn)
			if err != nil {
				return withExitCode(exitcode.OperationFailed, err)
			}
			lines := unitLines(conn, dest)
			switch format {
			case "json":
				return writeIndentedJSON(c.OutOrStdout(), map[string]any{"lines": lines})
			case "ini":
				fmt.Fprintf(c.OutOrStdout(), "[Service]\n%s\n", strings.Join(lines, "\n"))
				return nil
			}
			return NewUsageError("service render-unit-lines: --format must be json or ini")
		},
	}
	cmd.Flags().String("format", "ini", "output format: json or ini")
	cmd.Flags().String("scope", "", "system or user (default: the connection's enrollment, else system)")
	return cmd
}
