package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/brokerd"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	linuxpkg "github.com/keylatch/keylatch/packaging/linux"
)

// brokerEuid is the effective user id the installer checks; tests replace it so
// a run as root never installs anything.
var brokerEuid = os.Geteuid

// brokerCaller sends requests to the system broker; *control.Client is one.
type brokerCaller interface {
	Call(brokerapi.Request) (brokerapi.Response, error)
}

// The seams tests replace to run the commands without a daemon.
var (
	brokerInstalled = control.BrokerInstalled
	dialBroker      = func(env llmcontext.Lookup) (brokerCaller, error) {
		c, err := control.NewClient(env)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	// dialRawBroker is dialBroker for the session ticket verifier, which must
	// not classify the environment: that would call the verifier again.
	dialRawBroker = func(env llmcontext.Lookup) (brokerCaller, error) {
		c, err := control.NewRawClient(env)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
)

// brokerClient connects to the system broker. It fails when the broker is not
// installed, so a command that needs it never falls back to local key files.
func brokerClient(env llmcontext.Lookup) (brokerCaller, error) {
	if !brokerInstalled(env) {
		return nil, NewUsageError("the system broker is not installed; run 'sudo keylatch broker install' (Linux with systemd)")
	}
	c, err := dialBroker(env)
	if err != nil {
		return nil, withExitCode(exitcode.OperationFailed, err)
	}
	return c, nil
}

// brokerFailure turns a refused broker reply into the CLI error that names it.
func brokerFailure(op string, resp brokerapi.Response) error {
	msg := fmt.Sprintf("%s: %s", op, resp.Error)
	switch resp.Code {
	case brokerapi.CodePresenceRequired, brokerapi.CodeRefused:
		return NewSecurityBlock("%s", msg)
	case brokerapi.CodeNotFound:
		return withExitCode(exitcode.Missing, errors.New(msg))
	case brokerapi.CodeBadRequest:
		return NewUsageError("%s", msg)
	}
	return withExitCode(exitcode.OperationFailed, errors.New(msg))
}

func withExitCodeOperation(op string, err error) error {
	return withExitCode(exitcode.OperationFailed, fmt.Errorf("%s: %w", op, err))
}

// brokerPrivileged asks the daemon for presence on req and sends it with the
// proof. The daemon builds the sentence the human reads from the request.
func brokerPrivileged(c brokerCaller, op string, req brokerapi.Request) (brokerapi.Response, error) {
	proven, err := brokerd.Prove(c, req)
	if err != nil {
		return brokerapi.Response{}, NewSecurityBlock("%s: %v", op, err)
	}
	resp, err := c.Call(proven)
	if err != nil {
		return resp, withExitCode(exitcode.OperationFailed, fmt.Errorf("%s: %w", op, err))
	}
	if !resp.OK {
		return resp, brokerFailure(op, resp)
	}
	return resp, nil
}

func newBrokerInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Install the system broker (needs root; Linux with systemd)",
		Long: `Install the system broker: the keylatch system user, the keylatchd service and
socket units, the polkit policy and a device root sealed with systemd-creds
(TPM2 and the host key when a TPM exists, the host key otherwise). Then start
the socket. Run it with sudo, once. It never replaces an existing device root.

Presence is asked of you through polkit: your own password, every time. After
installing, run 'keylatch broker adopt' to move your secrets into the broker.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if runtime.GOOS != "linux" {
				return NewUsageError("broker install: the system broker runs on Linux only")
			}
			in := &brokerd.Installer{Root: "/", Files: linuxpkg.Files, Run: brokerd.ExecRunner{}, Euid: brokerEuid, Out: c.OutOrStdout()}
			res, err := in.Install(c.Context())
			if err != nil {
				if errors.Is(err, brokerd.ErrNotRoot) {
					return NewSecurityBlock("%v", err)
				}
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("broker install: %w", err))
			}
			for _, f := range res.Written {
				fmt.Fprintf(c.OutOrStdout(), "installed %s\n", f)
			}
			for _, f := range res.Kept {
				fmt.Fprintf(c.OutOrStdout(), "kept      %s\n", f)
			}
			fmt.Fprintln(c.OutOrStdout(), "broker socket started: /run/keylatch/broker.sock")
			fmt.Fprintln(c.OutOrStdout(), "next: keylatch broker adopt")
			return nil
		},
	}
}

func newBrokerAdoptCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "adopt",
		Short: "Move your in-user secrets and policy into the broker",
		Long: `Move the secrets, the policy and the audit position of your in-user install into
the broker. Every secret is checked with a keyed hash after the move; only then
are your gateway tokens revoked and your in-user key material (the vault
identity, keyring, signing key and audit salt) shredded.

The move needs your presence (polkit, your own password). Every upstream key
that sat in your account is listed afterwards with 'rotate recommended': a
process of your account could have read it.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			bc, err := brokerClient(env)
			if err != nil {
				return err
			}
			src := newUserSource(c, env)
			res, err := brokerd.Adopt(c.Context(), src, bc, nil)
			if err != nil {
				if errors.Is(err, brokerd.ErrVerify) {
					return withExitCode(exitcode.OperationFailed, fmt.Errorf("broker adopt: %w; your in-user install was left untouched", err))
				}
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("broker adopt: %w", err))
			}
			if err := brokerapi.WriteAdopted(paths.BrokerAdopted(env), brokerapi.Adopted{At: time.Now().UTC(), UpstreamKey: res.RotateUpstream}); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "broker adopt: the adoption marker was not written: %v\n", err)
			}
			if asJSON, _ := c.Root().PersistentFlags().GetBool("json"); asJSON {
				return json.NewEncoder(c.OutOrStdout()).Encode(res)
			}
			fmt.Fprintf(c.OutOrStdout(), "adopted %d secret(s), %d verified; %d policy file(s); %d gateway token(s) revoked\n", res.Secrets, res.Verified, res.PolicyFiles, res.TokensRevoked)
			for _, f := range res.Shredded {
				fmt.Fprintf(c.OutOrStdout(), "shredded %s\n", f)
			}
			for _, p := range res.RotateUpstream {
				fmt.Fprintf(c.OutOrStdout(), "rotate recommended: %s\n", p)
			}
			return nil
		},
	}
}

func newBrokerExportToUserCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export-to-user",
		Short: "Copy the broker's secrets back into an in-user install (downgrade)",
		Long: `Create an in-user install if there is none and copy every secret the broker
holds for you back into it. The broker keeps its copy. Needs your presence.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			bc, err := brokerClient(env)
			if err != nil {
				return err
			}
			sink, cleanup, err := newUserSink(c, env)
			if err != nil {
				return err
			}
			defer cleanup()
			n, err := brokerd.ExportToUser(c.Context(), bc, sink)
			if err != nil {
				return withExitCode(exitcode.OperationFailed, fmt.Errorf("broker export-to-user: %w", err))
			}
			_ = os.Remove(paths.BrokerAdopted(env))
			fmt.Fprintf(c.OutOrStdout(), "restored %d secret(s) into your in-user install\n", n)
			return nil
		},
	}
}

func newBrokerRotateKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-keys",
		Short: "Rotate the broker master key",
		Long: `Replace the broker master key. Every wrapped key and every stored data key is
rewrapped; no stored value is re-encrypted. Needs your presence.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			bc, err := brokerClient(llmcontext.DefaultLookup)
			if err != nil {
				return err
			}
			resp, err := brokerPrivileged(bc, "broker rotate-keys", brokerapi.Request{Op: brokerapi.OpRotateKeys})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "master key rotated; now %s\n", resp.Status.KeyID)
			return nil
		},
	}
}

// brokerDaemonStatus is the daemon section of `broker status`.
type brokerDaemonStatus struct {
	Mode      string   `json:"mode"`
	Socket    string   `json:"socket,omitempty"`
	Reachable bool     `json:"reachable"`
	Error     string   `json:"error,omitempty"`
	Version   string   `json:"version,omitempty"`
	KeyID     string   `json:"key_id,omitempty"`
	Policy    string   `json:"policy,omitempty"`
	Presence  string   `json:"presence,omitempty"`
	Secrets   int      `json:"secrets,omitempty"`
	Leftovers []string `json:"in_user_leftovers,omitempty"`
}

// brokerDaemonState reports whether the system broker serves this user.
func brokerDaemonState(env llmcontext.Lookup) brokerDaemonStatus {
	st := brokerDaemonStatus{Mode: "in-user"}
	if !brokerInstalled(env) {
		return st
	}
	st.Mode, st.Socket = "broker", paths.BrokerSocket(env)
	c, err := dialBroker(env)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	resp, err := c.Call(brokerapi.Request{Op: brokerapi.OpStatus})
	if err != nil || !resp.OK || resp.Status == nil {
		st.Error = "the daemon did not answer a status request"
		return st
	}
	s := resp.Status
	st.Reachable, st.Version, st.KeyID, st.Policy, st.Presence, st.Secrets = true, s.Version, s.KeyID, s.Policy, s.Presence, s.Secrets
	st.Leftovers = inUserLeftovers(env)
	return st
}

func renderBrokerDaemon(w io.Writer, st brokerDaemonStatus) {
	fmt.Fprintf(w, "mode: %s\n", st.Mode)
	if st.Mode == "in-user" {
		fmt.Fprintln(w, "in-user mode: defense in depth, not a boundary; 'sudo keylatch broker install' installs the system broker")
		return
	}
	if !st.Reachable {
		fmt.Fprintf(w, "daemon: not reachable (%s)\n", st.Error)
		return
	}
	fmt.Fprintf(w, "daemon: %s, master key %s, policy %s, presence %s, %d secret(s)\n", st.Version, st.KeyID, st.Policy, st.Presence, st.Secrets)
	if len(st.Leftovers) > 0 {
		fmt.Fprintf(w, "in-user leftovers: %s\n", strings.Join(st.Leftovers, ", "))
	}
}

// inUserLeftovers names the in-user key files that still exist.
func inUserLeftovers(env llmcontext.Lookup) []string {
	var out []string
	for name, p := range map[string]string{
		"identity":     paths.KeyringIdentityPath(env),
		"keyring.json": paths.KeyringPath(env),
		"signing.key":  paths.GatewaySigningKey(env),
		"audit-salt":   paths.AuditSalt(env),
	} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}
