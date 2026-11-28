package cli

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/spf13/cobra"
)

const gatewayLaunchdLabel = "io.keylatch.gateway"

// gatewayLaunchdSpec is the macOS counterpart of the systemd unit: a LaunchAgent
// that runs `keylatch gateway up`; settings come from the operator config.
type gatewayLaunchdSpec struct {
	Binary, Home string
	Args         []string
	// OptIn is the unsupported-backend opt-in the agent carries.
	OptIn string
}

func xmlString(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func (s gatewayLaunchdSpec) render() string {
	var args strings.Builder
	for _, a := range append([]string{s.Binary}, s.Args...) {
		args.WriteString("        <string>" + xmlString(a) + "</string>\n")
	}
	env := ""
	if s.OptIn != "" {
		env = "    <key>EnvironmentVariables</key><dict><key>" + backend.AllowUnsupportedEnv + "</key><string>" + xmlString(s.OptIn) + "</string></dict>\n"
	}
	log := xmlString(filepath.Join(s.Home, "Library", "Logs", "keylatch-gateway.log"))
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>` + gatewayLaunchdLabel + `</string>
    <key>ProgramArguments</key>
    <array>
` + args.String() + `    </array>
` + env + `    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>` + log + `</string>
    <key>StandardErrorPath</key><string>` + log + `</string>
</dict>
</plist>
`
}

// gatewayServiceFlags are the flags `gateway install` takes: the shared
// settings (written to the operator config) and the backend credential wiring.
type gatewayServiceFlags struct {
	binary      string
	backendCred []string
	settings    gatewaySettingsFlags
}

func (f *gatewayServiceFlags) bind(cmd *cobra.Command) {
	f.settings.bind(cmd)
	cmd.Flags().StringVar(&f.binary, "binary", "", "absolute path of the keylatch binary (default: the running binary)")
	cmd.Flags().StringArrayVar(&f.backendCred, "backend-credential", nil, "<cred-name>=<ENV_VAR>, repeatable: read the secret from the login Keychain (service \"keylatch-backend\", account <cred-name>) at start and export it as ENV_VAR")
}

func (f *gatewayServiceFlags) used(c *cobra.Command) bool {
	for _, n := range []string{"listen", "allow-source", "allow-any-source", "github-mint", "backend-credential", "binary"} {
		if c.Flags().Changed(n) {
			return true
		}
	}
	return false
}

func (f *gatewayServiceFlags) launchdSpec(home string) (gatewayLaunchdSpec, error) {
	bin, err := resolveGatewayBinary(f.binary)
	if err != nil {
		return gatewayLaunchdSpec{}, err
	}
	if err := validateUnitPath(bin); err != nil {
		return gatewayLaunchdSpec{}, err
	}
	creds, err := parseBackendCredentials(f.backendCred)
	if err != nil {
		return gatewayLaunchdSpec{}, err
	}
	return gatewayLaunchdSpec{Binary: bin, Home: home, Args: strings.Fields(gatewayExecArgs(creds)), OptIn: backend.OptInEnvValue()}, nil
}

// installGatewayLaunchd writes and loads the gateway LaunchAgent.
func installGatewayLaunchd(c *cobra.Command, f *gatewayServiceFlags) error {
	if runtime.GOOS != "darwin" {
		return NewUsageError("gateway install --listen: the LaunchAgent is macOS only; on Linux use `keylatch gateway systemd install`")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("gateway install: %w", err)
	}
	spec, err := f.launchdSpec(home)
	if err != nil {
		return err
	}
	if err := f.settings.persist(c); err != nil {
		return err
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", gatewayLaunchdLabel+".plist")
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil { //nolint:gosec // LaunchAgents is the standard 0755 directory
		return fmt.Errorf("gateway install: %w", err)
	}
	if err := os.WriteFile(plistPath, []byte(spec.render()), 0o644); err != nil { //nolint:gosec // plists carry no secrets
		return fmt.Errorf("gateway install: write %q: %w", plistPath, err)
	}
	if _, err := launchctlRunFunc("list", gatewayLaunchdLabel); err == nil {
		_, _ = launchctlRunFunc("unload", plistPath)
	}
	if out, err := launchctlRunFunc("load", "-w", plistPath); err != nil {
		return fmt.Errorf("gateway install: launchctl load: %v: %s", err, strings.TrimSpace(string(out)))
	}
	fmt.Fprintf(c.OutOrStdout(), "  gateway installed and loaded from %s\n", filepath.Base(plistPath))
	return nil
}
