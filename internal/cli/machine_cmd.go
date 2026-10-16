package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/machinecert"
)

// writeBundle writes the credential file's content; tests replace it to
// simulate a full disk.
var writeBundle = func(f *os.File, b []byte) error {
	_, err := f.Write(b)
	return err
}

func requireHumanMachine(what string) error {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return NewSecurityBlock("keylatch machine %s decides which remote machines may use a domain's credentials and needs a human. Ask the person at the machine to run it in a terminal.", what)
	}
	return nil
}

func newMachineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "machine",
		Short: "Issue credentials that let a remote machine call a domain's connections",
		Long: `Issue, revoke and list machine credentials. A credential is an Ed25519 key pair
and a certificate signed by the system broker's machine CA; the certificate
names one domain (namespace), the capabilities the machine holds and its expiry.
The private key is made on this host and never sent to the broker.

The machine presents the file with 'keylatch call --remote <addr> --machine-key
<file> <connection> <action>'. The broker serves it over mutual TLS 1.3 on the
address set with 'keylatch config set gateway.machine_listen <host:port>', checks
revocation on every request and uses only the certificate's domain.`,
	}
	cmd.AddCommand(newMachineIssueCmd(), newMachineRevokeCmd(), newMachineListCmd())
	return cmd
}

func newMachineIssueCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "issue --domain <namespace> --name <name> --caps <c1,c2> --ttl <duration> --out <file>",
		Short: "Issue a machine credential (needs your presence)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if err := requireHumanMachine("issue"); err != nil {
				return err
			}
			domain, _ := c.Flags().GetString("domain")
			name, _ := c.Flags().GetString("name")
			caps, _ := c.Flags().GetStringSlice("caps")
			ttl, _ := c.Flags().GetDuration("ttl")
			out, _ := c.Flags().GetString("out")
			if out == "" {
				return NewUsageError("machine issue: --out is required")
			}
			// The file is created first, exclusively and without following a
			// symlink, so the credential never lands somewhere another file
			// pointed at and nothing is issued when it cannot be written.
			f, err := os.OpenFile(filepath.Clean(out), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the destination is the caller's own argument
			if err != nil {
				if errors.Is(err, os.ErrExist) {
					return NewUsageError("machine issue: %s exists; remove it or choose another file", out)
				}
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("machine issue: %w", err))
			}
			issued := false
			defer func() {
				_ = f.Close()
				if !issued {
					_ = os.Remove(out)
				}
			}()
			bc, err := brokerClient(llmcontext.DefaultLookup)
			if err != nil {
				return err
			}
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return withExitCode(exitcode.OperationFailed, err)
			}
			defer clear(key)
			resp, err := brokerPrivileged(bc, "machine issue", brokerapi.Request{Op: brokerapi.OpMachineIssue, Machine: &brokerapi.MachineRequest{
				Name: name, Domain: domain, Caps: caps, TTLSeconds: int64(ttl / time.Second), PublicKey: pub,
			}})
			if err != nil {
				return err
			}
			if resp.Machine == nil {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("machine issue: the broker sent no certificate"))
			}
			keyPEM, err := machinecert.PrivatePEM(key)
			if err != nil {
				return withExitCode(exitcode.OperationFailed, err)
			}
			defer clear(keyPEM)
			bundle := append(append(append([]byte(nil), keyPEM...), resp.Machine.Certificate...), resp.Machine.CA...)
			defer clear(bundle)
			if err := writeBundle(f, bundle); err != nil {
				// The broker already recorded the certificate; withdraw it so
				// no credential exists that nobody holds.
				_, rerr := brokerPrivileged(bc, "machine revoke", brokerapi.Request{Op: brokerapi.OpMachineRevoke, Machine: &brokerapi.MachineRequest{Name: name}})
				if rerr != nil {
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("machine issue: write %s: %w; the broker still lists %q, revoke it with 'keylatch machine revoke %s'", out, err, name, name))
				}
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("machine issue: write %s: %w; the credential was revoked", out, err))
			}
			issued = true
			fmt.Fprintf(c.OutOrStdout(), "issued %s for domain %s (%s), valid %s; credential file %s\n", name, domain, strings.Join(caps, ","), ttl, out)
			return nil
		},
	}
	cmd.Flags().String("domain", "", "namespace the machine may use (required)")
	cmd.Flags().String("name", "", "machine name: lower-case letters, digits and dashes (required)")
	cmd.Flags().StringSlice("caps", []string{"call"}, "capabilities the machine holds")
	cmd.Flags().Duration("ttl", 24*time.Hour, "how long the credential is valid")
	cmd.Flags().String("out", "", "file to write the key and certificate to (required)")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newMachineRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke a machine credential (needs your presence)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := requireHumanMachine("revoke"); err != nil {
				return err
			}
			bc, err := brokerClient(llmcontext.DefaultLookup)
			if err != nil {
				return err
			}
			if _, err := brokerPrivileged(bc, "machine revoke", brokerapi.Request{Op: brokerapi.OpMachineRevoke, Machine: &brokerapi.MachineRequest{Name: args[0]}}); err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "revoked %s\n", args[0])
			return nil
		},
	}
}

func newMachineListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List issued machine credentials",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			bc, err := brokerClient(llmcontext.DefaultLookup)
			if err != nil {
				return err
			}
			resp, err := bc.Call(brokerapi.Request{Op: brokerapi.OpMachineList, Machine: &brokerapi.MachineRequest{}})
			if err != nil {
				return withExitCodeOperation("machine list", err)
			}
			if !resp.OK || resp.Machine == nil {
				return brokerFailure("machine list", resp)
			}
			machines := resp.Machine.Machines
			if machines == nil {
				machines = []brokerapi.MachineInfo{}
			}
			if asJSON, _ := c.Flags().GetBool("json"); asJSON {
				return writeIndentedJSON(c.OutOrStdout(), map[string]any{"machines": machines})
			}
			tw := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
			for _, m := range machines {
				state := "active until " + m.NotAfter
				if m.Revoked {
					state = "revoked"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.Name, m.Domain, strings.Join(m.Caps, ","), state)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().Bool("json", false, "print JSON")
	return cmd
}

const machineListenKey = "gateway.machine_listen"

// setMachineListen asks the broker to bind the machine listener. The address
// is checked here and again by the broker, which also asks for presence.
func setMachineListen(c *cobra.Command, addr string, allowWildcard bool) error {
	if err := requireHumanMachine("listen"); err != nil {
		return err
	}
	if err := gateway.ValidateMachineAddr(addr, allowWildcard); err != nil {
		return NewUsageError("config set %s: %v", machineListenKey, err)
	}
	bc, err := brokerClient(llmcontext.DefaultLookup)
	if err != nil {
		return err
	}
	if _, err := brokerPrivileged(bc, "config set", brokerapi.Request{Op: brokerapi.OpMachineListen, Machine: &brokerapi.MachineRequest{Listen: addr, AllowWildcard: allowWildcard}}); err != nil {
		return err
	}
	fmt.Fprintf(c.OutOrStdout(), "set %s=%s\n", machineListenKey, addr)
	return nil
}
