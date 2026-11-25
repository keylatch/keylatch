package cli

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
type unitBackendCredential struct{ Name, File string }

type gatewayUnitSpec struct {
	Binary         string
	CredentialFile string
	// BackendCredentials are sealed secrets a backend reads from its
	// environment, each loaded as a systemd credential.
	BackendCredentials []unitBackendCredential
	// ExecArgs are the arguments after the binary: `gateway up` plus the
	// backend credential wiring. Settings live in the operator config.
	ExecArgs string
}

var gatewayUnitTemplate = template.Must(template.New("unit").Parse(`[Unit]
Description=Keylatch gateway
Documentation=https://github.com/keylatch/keylatch/blob/main/docs/runtime-modes.md

[Service]
Type=simple
# Listen address, allowed sources, mint connection and proxy listeners are read from the
# operator config (keylatch gateway config get); changing them needs a restart, not a reinstall.
# The vault key is a systemd credential decrypted for this service only, so the
# vault opens without a login session, keyring or plaintext key file.
LoadCredentialEncrypted={{.Credential}}:{{.CredentialFile}}
Environment=KEYLATCH_AGE_IDENTITY=%d/{{.Credential}}
{{- range .BackendCredentials}}
# Backend secret, sealed the same way. keylatch reads it from $CREDENTIALS_DIRECTORY
# at start and keeps it in its own process environment only.
LoadCredentialEncrypted={{.Name}}:{{.File}}
{{- end}}
ExecStart={{.Binary}} {{.ExecArgs}}
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
		return fmt.Errorf("listen address %q: host must be an IP address (for example the address of a VM or container network), not %q", addr, host)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("listen address %q binds every interface; use an address of the network the callers are on", addr)
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

func gatewayCredentialPath(env llmcontext.Lookup) string {
	return filepath.Join(paths.GatewayDir(env), "kek.cred")
}

var connectionNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// gatewayExecArgs builds the service command line: `gateway up` and the
// backend credential wiring only. Everything else is read from the operator config.
func gatewayExecArgs(backendCreds []backendCredential) string {
	args := []string{"gateway", "up"}
	for _, c := range backendCreds {
		args = append(args, "--backend-credential", c.flag())
	}
	return strings.Join(args, " ")
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

Use --with-key=host (or omit --with-key) on machines without a TPM2.

To let a backend authenticate without anyone present (long unattended runs), seal its
secret the same way and pass it with --backend-credential <cred-name>=<ENV_VAR>:<file>.
ENV_VAR must be one a backend reads (for example OP_SERVICE_ACCOUNT_TOKEN for a
1Password service account, BW_SESSION, VAULT_TOKEN, DOPPLER_TOKEN). The secret is read
from stdin, never from argv:

  systemd-creds encrypt --user --name=op-sa --with-key=tpm2 - \
    ~/.config/keylatch/gateway/op-sa.cred
  keylatch gateway systemd install ... \
    --backend-credential op-sa=OP_SERVICE_ACCOUNT_TOKEN:$HOME/.config/keylatch/gateway/op-sa.cred

Paste the secret, then press Ctrl-D twice (or pipe it from a password manager).`,
	}
	cmd.AddCommand(newGatewaySystemdPrintCmd(), newGatewaySystemdInstallCmd(), newGatewaySystemdUninstallCmd(), newGatewaySystemdStatusCmd())
	return cmd
}

type gatewaySystemdFlags struct {
	binary      string
	backendCred []string
	settings    gatewaySettingsFlags
}

func (f *gatewaySystemdFlags) bind(cmd *cobra.Command) {
	f.settings.bind(cmd)
	cmd.Flags().StringVar(&f.binary, "binary", "", "absolute path of the keylatch binary (default: the running binary)")
	cmd.Flags().StringArrayVar(&f.backendCred, "backend-credential", nil, "<cred-name>=<ENV_VAR>:<file.cred>, repeatable: a systemd-creds sealed secret exported as ENV_VAR from $CREDENTIALS_DIRECTORY at start (the name must match systemd-creds --name)")
}

func (f *gatewaySystemdFlags) spec(env llmcontext.Lookup) (gatewayUnitSpec, error) {
	bin, err := resolveGatewayBinary(f.binary)
	if err != nil {
		return gatewayUnitSpec{}, err
	}
	var backendCreds []backendCredential
	var unitCreds []unitBackendCredential
	for _, v := range f.backendCred {
		head, file, ok := strings.Cut(v, ":")
		if !ok || file == "" {
			return gatewayUnitSpec{}, fmt.Errorf("--backend-credential %q: use <cred-name>=<ENV_VAR>:<file.cred>", v)
		}
		parsed, err := parseBackendCredentials([]string{head})
		if err != nil {
			return gatewayUnitSpec{}, err
		}
		backendCreds = append(backendCreds, parsed[0])
		unitCreds = append(unitCreds, unitBackendCredential{parsed[0].Name, file})
	}
	if _, err := parseBackendCredentials(credFlags(backendCreds)); err != nil {
		return gatewayUnitSpec{}, err
	}
	spec := gatewayUnitSpec{ExecArgs: gatewayExecArgs(backendCreds), Binary: bin, CredentialFile: gatewayCredentialPath(env), BackendCredentials: unitCreds}
	unitPaths := []string{spec.Binary, spec.CredentialFile}
	for _, c := range spec.BackendCredentials {
		unitPaths = append(unitPaths, c.File)
	}
	for _, p := range unitPaths {
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
			if _, _, _, err := f.settings.effective(c); err != nil {
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
		Short: "Write the user unit (and, with settings flags, the gateway settings into the operator config)",
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
			if err := f.settings.persist(c); err != nil {
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
			fmt.Fprintf(c.OutOrStdout(), "wrote %s\n", unitPath)

			if out, err := systemctlRunFunc("daemon-reload"); err != nil {
				return fmt.Errorf("gateway systemd install: systemctl daemon-reload: %v: %s", err, strings.TrimSpace(string(out)))
			}
			if _, err := os.Stat(spec.CredentialFile); errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(c.OutOrStdout(), "vault key credential missing at %s; see 'keylatch gateway systemd --help' to create it before starting\n", spec.CredentialFile)
			}
			for _, bc := range spec.BackendCredentials {
				if _, err := os.Stat(bc.File); errors.Is(err, os.ErrNotExist) {
					fmt.Fprintf(c.OutOrStdout(), "backend credential %s missing at %s; see 'keylatch gateway systemd --help' to create it before starting\n", bc.Name, bc.File)
				}
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
		Short: "Stop and remove the user unit (keeps the config and credentials)",
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
	var checkBackend bool
	cmd := &cobra.Command{
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

			report("credential", present(gatewayCredentialPath(env)))
			linger := "unknown"
			if out, err := loginctlRunFunc("show-user", currentUserName(), "--property=Linger", "--value"); err == nil {
				linger = strings.TrimSpace(string(out))
			}
			report("linger", linger+" (must be yes to run without a login session)")
			creds, files := unitBackendCredentials(filepath.Join(unitDir, systemdUnitName))
			for _, bc := range creds {
				report("backend cred", bc.Name+" -> "+bc.Env+" "+present(files[bc.Name]))
				if checkBackend {
					report("backend auth", bc.Name+": "+checkSealedBackendCredential(c.Context(), bc, files[bc.Name]))
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkBackend, "check-backend", false, "decrypt each sealed backend credential for this command only and verify it (1Password: `op whoami`); the value is never printed")
	return cmd
}

func currentUserName() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return fmt.Sprint(os.Getuid())
}

func credFlags(cs []backendCredential) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.flag())
	}
	return out
}
