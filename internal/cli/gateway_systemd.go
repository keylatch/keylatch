package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

const (
	systemdUnitName      = "keylatch-gateway.service"
	systemdCredentialKEK = "kek"
)

// systemctlRunFunc and loginctlRunFunc are vars so tests substitute fakes and
// never talk to the real service manager.
var (
	systemctlRunFunc = func(args ...string) ([]byte, error) {
		return exec.Command("systemctl", append([]string{"--user"}, args...)...).CombinedOutput() //nolint:gosec // args are fixed, non-user-controlled
	}
	loginctlRunFunc = func(args ...string) ([]byte, error) {
		return exec.Command("loginctl", args...).CombinedOutput() //nolint:gosec // args are fixed, non-user-controlled
	}
)

// gatewayUnitSpec is everything the unit template needs; all paths are absolute.
type gatewayUnitSpec struct {
	Binary         string
	EnvFile        string
	CredentialFile string
}

var gatewayUnitTemplate = template.Must(template.New("unit").Parse(`[Unit]
Description=Keylatch gateway
Documentation=https://github.com/keylatch/keylatch/blob/main/docs/runtime-modes.md

[Service]
Type=simple
# KEYLATCH_GATEWAY_LISTEN (the bridge address) comes from this file. Without it
# the gateway binds loopback only; the unit never binds 0.0.0.0.
EnvironmentFile={{.EnvFile}}
# The vault key is a systemd credential decrypted for this service only, so the
# vault opens without a login session, keyring or plaintext key file.
LoadCredentialEncrypted={{.Credential}}:{{.CredentialFile}}
Environment=KEYLATCH_AGE_IDENTITY=%d/{{.Credential}}
ExecStart={{.Binary}} gateway up
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=default.target
`))

func (s gatewayUnitSpec) render() (string, error) {
	var b strings.Builder
	err := gatewayUnitTemplate.Execute(&b, struct {
		gatewayUnitSpec
		Credential string
	}{s, systemdCredentialKEK})
	return b.String(), err
}

// validateGatewayListen accepts only an explicit IP literal and port: a
// wildcard or hostname would expose the gateway beyond the intended interface.
func validateGatewayListen(addr string) error {
	if err := validateHostPort(addr); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("listen address %q: host must be an IP address (for example the VM bridge address), not %q", addr, host)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("listen address %q binds every interface; use the bridge address", addr)
	}
	return nil
}

// validateUnitPath rejects characters that systemd would expand or split on.
func validateUnitPath(p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path %q must be absolute", p)
	}
	if strings.ContainsAny(p, "%$\"'\\ \t\r\n") {
		return fmt.Errorf("path %q contains a character that is unsafe in a unit file", p)
	}
	return nil
}

func systemdUserUnitDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "systemd", "user"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user"), nil
}

func gatewayEnvFilePath(env llmcontext.Lookup) string {
	return filepath.Join(paths.GatewayDir(env), "systemd.env")
}

func gatewayCredentialPath(env llmcontext.Lookup) string {
	return filepath.Join(paths.GatewayDir(env), "kek.cred")
}

func gatewayEnvFileContent(listen string) string {
	return "# Address the gateway binds. Use the VM bridge address, never 0.0.0.0.\n" +
		"KEYLATCH_GATEWAY_LISTEN=" + listen + "\n" +
		"# Callers outside this CIDR are refused once the gateway supports a source\n" +
		"# allowlist. This build does not read it yet.\n" +
		"# KEYLATCH_GATEWAY_ALLOW_SOURCE=192.168.122.0/24\n"
}

func resolveGatewayBinary(flag string) (string, error) {
	bin := flag
	if bin == "" {
		self, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("resolve keylatch binary: %w", err)
		}
		bin = self
	}
	resolved, err := filepath.EvalSymlinks(bin)
	if err != nil {
		return "", fmt.Errorf("resolve keylatch binary %q: %w", bin, err)
	}
	return resolved, nil
}

func newGatewaySystemdCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "systemd",
		Short: "Run the gateway as a systemd user service (Linux)",
		Long: `Manage a systemd user unit that runs 'keylatch gateway up'.

The vault key is delivered as an encrypted systemd credential (TPM2 and/or the
host key), so the unit starts at boot without a login session or OS keyring.
Enable lingering for the user ('loginctl enable-linger') so the user manager
runs before login. --insecure-file-kek is never used.

Provision the credential once, before 'keylatch bootstrap':

  umask 077
  head -c 32 /dev/urandom > "$XDG_RUNTIME_DIR/kek"
  systemd-creds encrypt --user --name=kek --with-key=tpm2 \
    "$XDG_RUNTIME_DIR/kek" ~/.config/keylatch/gateway/kek.cred
  KEYLATCH_AGE_IDENTITY="$XDG_RUNTIME_DIR/kek" keylatch bootstrap
  shred -u "$XDG_RUNTIME_DIR/kek"

Use --with-key=host (or omit --with-key) on machines without a TPM2.`,
	}
	cmd.AddCommand(newGatewaySystemdPrintCmd(), newGatewaySystemdInstallCmd(), newGatewaySystemdUninstallCmd(), newGatewaySystemdStatusCmd())
	return cmd
}

type gatewaySystemdFlags struct {
	listen string
	binary string
}

func (f *gatewaySystemdFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.listen, "listen", "", "address:port the gateway binds, an IP literal such as the VM bridge address (required)")
	cmd.Flags().StringVar(&f.binary, "binary", "", "absolute path of the keylatch binary (default: the running binary)")
	_ = cmd.MarkFlagRequired("listen")
}

func (f *gatewaySystemdFlags) spec(env llmcontext.Lookup) (gatewayUnitSpec, error) {
	if err := validateGatewayListen(f.listen); err != nil {
		return gatewayUnitSpec{}, err
	}
	bin, err := resolveGatewayBinary(f.binary)
	if err != nil {
		return gatewayUnitSpec{}, err
	}
	spec := gatewayUnitSpec{Binary: bin, EnvFile: gatewayEnvFilePath(env), CredentialFile: gatewayCredentialPath(env)}
	for _, p := range []string{spec.Binary, spec.EnvFile, spec.CredentialFile} {
		if err := validateUnitPath(p); err != nil {
			return gatewayUnitSpec{}, err
		}
	}
	return spec, nil
}

func newGatewaySystemdPrintCmd() *cobra.Command {
	var f gatewaySystemdFlags
	cmd := &cobra.Command{
		Use:   "print",
		Short: "Print the unit file without installing it",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			spec, err := f.spec(llmcontext.DefaultLookup)
			if err != nil {
				return err
			}
			unit, err := spec.render()
			if err != nil {
				return err
			}
			fmt.Fprint(c.OutOrStdout(), unit)
			return nil
		},
	}
	f.bind(cmd)
	return cmd
}

func newGatewaySystemdInstallCmd() *cobra.Command {
	var (
		f   gatewaySystemdFlags
		now bool
	)
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Write the user unit and gateway environment file",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			spec, err := f.spec(env)
			if err != nil {
				return err
			}
			unit, err := spec.render()
			if err != nil {
				return err
			}
			unitDir, err := systemdUserUnitDir()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(unitDir, 0o755); err != nil { //nolint:gosec // user unit directory, same mode systemd uses
				return fmt.Errorf("gateway systemd install: mkdir %q: %w", unitDir, err)
			}
			unitPath := filepath.Join(unitDir, systemdUnitName)
			if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil { //nolint:gosec // unit files carry no secrets
				return fmt.Errorf("gateway systemd install: write %q: %w", unitPath, err)
			}
			if err := os.MkdirAll(filepath.Dir(spec.EnvFile), 0o700); err != nil {
				return fmt.Errorf("gateway systemd install: mkdir: %w", err)
			}
			if err := os.WriteFile(spec.EnvFile, []byte(gatewayEnvFileContent(f.listen)), 0o600); err != nil {
				return fmt.Errorf("gateway systemd install: write %q: %w", spec.EnvFile, err)
			}
			fmt.Fprintf(c.OutOrStdout(), "wrote %s\nwrote %s\n", unitPath, spec.EnvFile)

			if out, err := systemctlRunFunc("daemon-reload"); err != nil {
				return fmt.Errorf("gateway systemd install: systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
			}
			if _, err := os.Stat(spec.CredentialFile); errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(c.OutOrStdout(), "vault key credential missing at %s; see 'keylatch gateway systemd --help' to create it before starting\n", spec.CredentialFile)
			}
			if now {
				if out, err := systemctlRunFunc("enable", "--now", systemdUnitName); err != nil {
					return fmt.Errorf("gateway systemd install: systemctl enable --now: %v: %s", err, strings.TrimSpace(string(out)))
				}
				fmt.Fprintln(c.OutOrStdout(), "enabled and started "+systemdUnitName)
			} else {
				fmt.Fprintln(c.OutOrStdout(), "not started; run 'systemctl --user enable --now "+systemdUnitName+"' when the credential exists")
			}
			return nil
		},
	}
	f.bind(cmd)
	cmd.Flags().BoolVar(&now, "now", false, "also enable and start the unit")
	return cmd
}

func newGatewaySystemdUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the user unit (keeps the environment file and credential)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			unitDir, err := systemdUserUnitDir()
			if err != nil {
				return err
			}
			unitPath := filepath.Join(unitDir, systemdUnitName)
			if _, err := os.Stat(unitPath); errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(c.OutOrStdout(), "not installed")
				return nil
			}
			// A unit that was never enabled or started makes these fail harmlessly.
			_, _ = systemctlRunFunc("disable", "--now", systemdUnitName)
			if err := os.Remove(unitPath); err != nil {
				return fmt.Errorf("gateway systemd uninstall: %w", err)
			}
			if out, err := systemctlRunFunc("daemon-reload"); err != nil {
				return fmt.Errorf("gateway systemd uninstall: systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
			}
			fmt.Fprintf(c.OutOrStdout(), "removed %s\n", unitPath)
			return nil
		},
	}
}

func newGatewaySystemdStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the unit is installed, enabled, active and able to unlock the vault",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			env := llmcontext.DefaultLookup
			w := c.OutOrStdout()
			unitDir, err := systemdUserUnitDir()
			if err != nil {
				return err
			}
			report := func(label, value string) { fmt.Fprintf(w, "%-12s %s\n", label, value) }
			state := func(args ...string) string {
				out, _ := systemctlRunFunc(args...)
				if s := strings.TrimSpace(string(out)); s != "" {
					return s
				}
				return "unknown"
			}
			present := func(p string) string {
				if _, err := os.Stat(p); err != nil {
					return "missing (" + p + ")"
				}
				return "present (" + p + ")"
			}
			report("unit", present(filepath.Join(unitDir, systemdUnitName)))
			report("enabled", state("is-enabled", systemdUnitName))
			report("active", state("is-active", systemdUnitName))
			report("env file", present(gatewayEnvFilePath(env)))
			report("credential", present(gatewayCredentialPath(env)))
			linger := "unknown"
			if out, err := loginctlRunFunc("show-user", currentUserName(), "--property=Linger", "--value"); err == nil {
				linger = strings.TrimSpace(string(out))
			}
			report("linger", linger+" (must be yes to run without a login session)")
			return nil
		},
	}
}

func currentUserName() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return fmt.Sprint(os.Getuid())
}
