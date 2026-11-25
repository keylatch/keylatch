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

	"github.com/keylatch/keylatch/internal/gateway"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

// defaultProxyPort is the proxy port when --with-proxy names no address (the
// gateway uses 8788; 8789 is taken by another service on the bridge).
const defaultProxyPort = "8790"

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
	EnvFile        string
	CredentialFile string
	// BackendCredentials are sealed secrets a backend reads from its
	// environment, each loaded as a systemd credential.
	BackendCredentials []unitBackendCredential
	// ExecArgs are the arguments after the binary: gateway up plus the
	// validated --allow-source and --github-mint flags.
	ExecArgs string
}

var gatewayUnitTemplate = template.Must(template.New("unit").Parse(`[Unit]
Description=Keylatch gateway
Documentation=https://github.com/keylatch/keylatch/blob/main/docs/runtime-modes.md

[Service]
Type=simple
# KEYLATCH_GATEWAY_LISTEN (the bridge address) comes from this file. Without it
# the gateway binds loopback only; the unit never binds every interface.
EnvironmentFile={{.EnvFile}}
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
	return "# Address the gateway binds. Use the VM bridge address, never a wildcard.\n" +
		"KEYLATCH_GATEWAY_LISTEN=" + listen + "\n"
}

var connectionNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// gatewayExecArgs builds the gateway command line. A non-loopback listen
// address needs --allow-source (canonical CIDR, so hostcheck-style parsers
// compare it exactly) unless allowAny is explicit.
func gatewayExecArgs(listen string, sources []string, allowAny bool, githubMint string, backendCreds []backendCredential, proxies []proxyListener) (string, error) {
	host, _, _ := net.SplitHostPort(listen)
	loopback := net.ParseIP(host).IsLoopback()
	if allowAny && len(sources) > 0 {
		return "", errors.New("--allow-any-source cannot be combined with --allow-source")
	}
	if !loopback && len(sources) == 0 && !allowAny {
		return "", fmt.Errorf("listen address %q is not loopback: pass --allow-source <CIDR> (for example the VM network) or, to accept any caller that can reach it, --allow-any-source", listen)
	}
	args := []string{"gateway", "up"}
	prefixes, err := gateway.ParseAllowSources(sources)
	if err != nil {
		return "", err
	}
	for _, p := range prefixes {
		args = append(args, "--allow-source", p.String())
	}
	if githubMint != "" {
		if !connectionNameRE.MatchString(githubMint) {
			return "", fmt.Errorf("--github-mint %q: connection names use letters, digits, '.', '_' and '-'", githubMint)
		}
		args = append(args, "--github-mint", githubMint)
	}
	seenProxy := map[string]bool{listen: true}
	for _, pl := range proxies {
		if err := validateGatewayListen(pl.Addr); err != nil {
			return "", fmt.Errorf("--proxy-listen: %w", err)
		}
		if seenProxy[pl.Addr] {
			return "", fmt.Errorf("--proxy-listen %q duplicates another listen address", pl.Addr)
		}
		seenProxy[pl.Addr] = true
		if !connectionNameRE.MatchString(pl.Connection) {
			return "", fmt.Errorf("--proxy-listen connection %q: connection names use letters, digits, '.', '_' and '-'", pl.Connection)
		}
		if ph, _, _ := net.SplitHostPort(pl.Addr); !net.ParseIP(ph).IsLoopback() && len(sources) == 0 {
			return "", fmt.Errorf("--proxy-listen %q is not loopback: pass --allow-source <CIDR>; --allow-any-source does not apply to the proxy", pl.Addr)
		}
		args = append(args, "--proxy-listen", pl.Addr+"="+pl.Connection)
	}
	for _, c := range backendCreds {
		args = append(args, "--backend-credential", c.flag())
	}
	return strings.Join(args, " "), nil
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
	listen      string
	binary      string
	sources     []string
	anySource   bool
	githubMint  string
	backendCred []string
	withProxy   bool
	proxyListen []string
}

func (f *gatewaySystemdFlags) bind(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.listen, "listen", "", "address:port the gateway binds, an IP literal such as the VM bridge address (required)")
	cmd.Flags().StringVar(&f.binary, "binary", "", "absolute path of the keylatch binary (default: the running binary)")
	cmd.Flags().StringArrayVar(&f.sources, "allow-source", nil, "CIDR callers must come from, repeatable; written to ExecStart as --allow-source <cidr> (required for a non-loopback --listen)")
	cmd.Flags().BoolVar(&f.anySource, "allow-any-source", false, "accept a non-loopback --listen without --allow-source (any caller that can reach the address)")
	cmd.Flags().StringVar(&f.githubMint, "github-mint", "", "github-app connection to serve POST /mint/github from (adds --github-mint to ExecStart)")
	cmd.Flags().StringArrayVar(&f.backendCred, "backend-credential", nil, "<cred-name>=<ENV_VAR>:<file.cred>, repeatable: a systemd-creds sealed secret exported as ENV_VAR from $CREDENTIALS_DIRECTORY at start (the name must match systemd-creds --name)")
	cmd.Flags().BoolVar(&f.withProxy, "with-proxy", false, "also run the GitHub-injecting CONNECT proxy in this unit (needs --proxy-listen and a github-app connection)")
	cmd.Flags().StringArrayVar(&f.proxyListen, "proxy-listen", nil, "proxy listener as <ip:port>[=<connection>], repeatable, one per GitHub installation (default with --with-proxy: <--listen host>:8790=<--github-mint connection>)")
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
	var proxies []proxyListener
	switch {
	case f.withProxy:
		values := f.proxyListen
		if len(values) == 0 {
			host, _, _ := net.SplitHostPort(f.listen)
			values = []string{net.JoinHostPort(host, defaultProxyPort)}
		}
		for _, v := range values {
			if !strings.Contains(v, "=") {
				if f.githubMint == "" {
					return gatewayUnitSpec{}, fmt.Errorf("--proxy-listen %q needs =<connection> (or --github-mint to default it)", v)
				}
				v += "=" + f.githubMint
			}
			pl, err := parseProxyListeners([]string{v})
			if err != nil {
				return gatewayUnitSpec{}, err
			}
			proxies = append(proxies, pl...)
		}
	case len(f.proxyListen) > 0:
		return gatewayUnitSpec{}, errors.New("--proxy-listen needs --with-proxy")
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
	execArgs, err := gatewayExecArgs(f.listen, f.sources, f.anySource, f.githubMint, backendCreds, proxies)
	if err != nil {
		return gatewayUnitSpec{}, err
	}
	spec := gatewayUnitSpec{ExecArgs: execArgs, Binary: bin, EnvFile: gatewayEnvFilePath(env), CredentialFile: gatewayCredentialPath(env), BackendCredentials: unitCreds}
	unitPaths := []string{spec.Binary, spec.EnvFile, spec.CredentialFile}
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
			report("env file", present(gatewayEnvFilePath(env)))
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
