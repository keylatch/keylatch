package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/keylatch/keylatch/internal/config"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/guard"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// checkExternalDocker checks Docker availability (only if gateway mode is "docker").
func checkExternalDocker(env llmcontext.Lookup, probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		cfgPath := paths.Config(env)
		cfg, err := config.Load(cfgPath)
		if err != nil {
			cfg = config.Default()
		}
		if cfg.Gateway == nil || cfg.Gateway.Mode != "docker" {
			return Status{
				Name:    "external.docker",
				Section: "daemon",
				OK:      true,
				Detail:  "docker check skipped (gateway mode is not 'docker')",
				Tags:    []string{"external", "docker"},
			}
		}
		p, ok, probeErr := probe.Find(ctx, "docker")
		if probeErr != nil {
			return Status{
				Name:    "external.docker",
				Section: "daemon",
				OK:      false,
				Detail:  fmt.Sprintf("error probing docker: %v", probeErr),
				Tags:    []string{"external", "docker"},
			}
		}
		if !ok {
			return Status{
				Name:    "external.docker",
				Section: "daemon",
				OK:      false,
				Detail:  "docker binary not found; required for gateway mode=docker",
				Fix:     "Install Docker: https://docs.docker.com/get-docker/",
				Tags:    []string{"external", "docker"},
			}
		}
		ver, _ := probe.Version(ctx, p)
		return Status{
			Name:    "external.docker",
			Section: "daemon",
			OK:      true,
			Detail:  fmt.Sprintf("docker_bin=%s version=%s", p, ver),
			Tags:    []string{"external", "docker"},
		}
	}
}

// checkExternalSOPS checks sops availability (only if config requests SOPS import/export).
func checkExternalSOPS(probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		p, ok, err := probe.Find(ctx, "sops")
		if err != nil {
			return Status{
				Name:    "external.sops",
				Section: "daemon",
				OK:      true,
				Warn:    true,
				Detail:  fmt.Sprintf("error probing sops: %v (optional)", err),
				Tags:    []string{"external", "sops"},
			}
		}
		if !ok {
			return Status{
				Name:    "external.sops",
				Section: "daemon",
				OK:      true,
				Detail:  "sops not found (optional; required only for SOPS import/export)",
				Tags:    []string{"external", "sops"},
			}
		}
		ver, _ := probe.Version(ctx, p)
		return Status{
			Name:    "external.sops",
			Section: "daemon",
			OK:      true,
			Detail:  fmt.Sprintf("sops_bin=%s version=%s", p, ver),
			Tags:    []string{"external", "sops"},
		}
	}
}

// checkACLKeychainUnlock is a placeholder for Phase 1.
func checkACLKeychainUnlock() Check {
	return func(_ context.Context) Status {
		return Status{
			Name:    "acl.keychain_unlock",
			Section: "providers",
			OK:      true,
			Warn:    true,
			Detail:  "keychain ACL unlock policy: not yet configured (Phase 1 placeholder)",
			Fix:     "Run `keylatch backend init` after Phase 1 ships.",
			Tags:    []string{"acl"},
		}
	}
}

// checkHookPreToolUse checks whether the keylatch pre-tool-use hook is installed
// in ~/.claude/settings.json. Best-effort, value-free.
func checkHookPreToolUse(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		home, err := os.UserHomeDir()
		if err != nil {
			return Status{
				Name:    "hook.preToolUse",
				Section: "environment",
				OK:      true,
				Warn:    true,
				Detail:  "could not determine home directory; skipping hook check",
				Tags:    []string{"hook"},
			}
		}

		settingsPath := filepath.Join(home, ".claude", "settings.json")
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			if os.IsNotExist(err) {
				return Status{
					Name:    "hook.preToolUse",
					Section: "environment",
					OK:      true,
					Warn:    true,
					Detail:  "~/.claude/settings.json not found; preToolUse hook not installed",
					Fix:     "Install the keylatch hook: see contrib/agent-guards/claude-code/README",
					Tags:    []string{"hook"},
				}
			}
			return Status{
				Name:    "hook.preToolUse",
				Section: "environment",
				OK:      true,
				Warn:    true,
				Detail:  fmt.Sprintf("could not read ~/.claude/settings.json: %v", err),
				Tags:    []string{"hook"},
			}
		}

		// Check for keylatch in the hooks section without revealing full paths.
		var settings map[string]any
		if jsonErr := json.Unmarshal(data, &settings); jsonErr != nil {
			return Status{
				Name:    "hook.preToolUse",
				Section: "environment",
				OK:      true,
				Warn:    true,
				Detail:  "~/.claude/settings.json could not be parsed",
				Tags:    []string{"hook"},
			}
		}

		// Look for "keylatch" keyword in the file (value-free check).
		if strings.Contains(string(data), "keylatch") {
			return Status{
				Name:    "hook.preToolUse",
				Section: "environment",
				OK:      true,
				Detail:  "keylatch preToolUse hook detected in ~/.claude/settings.json",
				Tags:    []string{"hook"},
			}
		}

		return Status{
			Name:    "hook.preToolUse",
			Section: "environment",
			OK:      true,
			Warn:    true,
			Detail:  "keylatch hook not found in ~/.claude/settings.json",
			Fix:     "Install the keylatch hook: see contrib/agent-guards/claude-code/README",
			Tags:    []string{"hook"},
		}
	}
}

// checkNoConnections is a soft WARN check that fires when no connections are configured.
// P1.8: warn the user to run setup or connect.
func checkNoConnections(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		vaultDir := paths.Vault(env)
		// Check if any connections exist by probing the connections prefix.
		connDir := filepath.Join(vaultDir, "default", "connections")
		info, err := os.Stat(connDir)
		if err != nil || !info.IsDir() {
			return Status{
				Name:    "connections.configured",
				Section: "providers",
				OK:      true,
				Warn:    true,
				Detail:  "no connections configured yet",
				Fix:     "Run `keylatch setup` or `keylatch connect <provider>` to add your first connection.",
				Tags:    []string{"connections"},
			}
		}
		// Check if directory has any subdirectories (providers).
		entries, err := os.ReadDir(connDir)
		if err != nil || len(entries) == 0 {
			return Status{
				Name:    "connections.configured",
				Section: "providers",
				OK:      true,
				Warn:    true,
				Detail:  "no connections configured yet",
				Fix:     "Run `keylatch setup` or `keylatch connect <provider>` to add your first connection.",
				Tags:    []string{"connections"},
			}
		}
		return Status{
			Name:    "connections.configured",
			Section: "providers",
			OK:      true,
			Detail:  fmt.Sprintf("connections directory exists at %s", connDir),
			Tags:    []string{"connections"},
		}
	}
}

// checkGatewayRunning is a soft WARN check that reports if the gateway is not running.
// P1.8: inform the user about gateway_typed runtime mode.
func checkGatewayRunning(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		pidPath := paths.GatewayPID(env)
		data, err := os.ReadFile(pidPath)
		if err != nil {
			return Status{
				Name:    "gateway.running",
				Section: "daemon",
				OK:      true,
				Warn:    true,
				Detail:  "gateway is not running (gateway.pid not found)",
				Fix:     "Run `keylatch gateway up` to enable gateway_typed runtime mode.",
				Tags:    []string{"gateway"},
			}
		}
		pidStr := strings.TrimSpace(string(data))
		if pidStr == "" {
			return Status{
				Name:    "gateway.running",
				Section: "daemon",
				OK:      true,
				Warn:    true,
				Detail:  "gateway is not running (empty gateway.pid)",
				Fix:     "Run `keylatch gateway up` to enable gateway_typed runtime mode.",
				Tags:    []string{"gateway"},
			}
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return Status{
				Name:    "gateway.running",
				Section: "daemon",
				OK:      true,
				Warn:    true,
				Detail:  fmt.Sprintf("gateway.pid contains non-numeric value %q", pidStr),
				Fix:     "Remove the stale PID file: rm " + pidPath,
				Tags:    []string{"gateway"},
			}
		}
		proc, err := os.FindProcess(pid)
		if err != nil || proc.Signal(syscall.Signal(0)) != nil {
			// Stale PID file — process is not running.
			return Status{
				Name:    "gateway",
				Section: "daemon",
				OK:      true,
				Warn:    true,
				Detail:  fmt.Sprintf("gateway PID file exists (pid=%d) but process is not running — stale file at %s", pid, pidPath),
				Fix:     "Remove the stale PID file: rm " + pidPath,
			}
		}
		return Status{
			Name:    "gateway.running",
			Section: "daemon",
			OK:      true,
			Detail:  fmt.Sprintf("gateway pid=%d", pid),
			Tags:    []string{"gateway"},
		}
	}
}

// checkCosignInstalled is a soft check that surfaces `keylatch verify --self`.
// §4.6: doctor reports whether cosign is available for binary verification.
func checkCosignInstalled(probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		p, ok, err := probe.Find(ctx, "cosign")
		if err != nil {
			return Status{
				Name:    "binary.cosign_verify",
				Section: "environment",
				OK:      true,
				Warn:    true,
				Detail:  fmt.Sprintf("error probing cosign: %v (optional)", err),
				Fix:     "Install cosign and run: keylatch verify --self",
				Tags:    []string{"security", "cosign"},
			}
		}
		if !ok {
			return Status{
				Name:    "binary.cosign_verify",
				Section: "environment",
				OK:      true,
				Warn:    true,
				Detail:  "cosign not found; binary signature cannot be verified",
				Fix:     "Install cosign (https://docs.sigstore.dev/cosign/installation/) then run: keylatch verify --self",
				Tags:    []string{"security", "cosign"},
			}
		}
		ver, _ := probe.Version(ctx, p)
		return Status{
			Name:    "binary.cosign_verify",
			Section: "environment",
			OK:      true,
			Detail:  fmt.Sprintf("cosign_bin=%s version=%s — run 'keylatch verify --self' to verify this binary", p, ver),
			Tags:    []string{"security", "cosign"},
		}
	}
}

// checkPlaintextRetention implements doctor check F3.
//
// T-12-03: F3 verifies that keylatchd does not retain credential plaintext
// after a run completes. The check:
//  1. Pings keylatchd on the default UI address.
//  2. If keylatchd is not running: reports [WARN] F3 with start hint.
//  3. If keylatchd is running: queries /v1/retention-canary (a memory inspection
//     endpoint added in T-12-03) with a generated canary token. If keylatchd
//     reports the canary is absent from live memory, the check passes.
//
// When the /v1/retention-canary endpoint is not present (pre-T-12-03 keylatchd),
// the check reports [WARN] F3 with an upgrade hint rather than failing.
func checkPlaintextRetention(env llmcontext.Lookup) Check {
	return func(ctx context.Context) Status {
		const checkName = "F3 plaintext_retention"
		const section = "daemon"

		// Resolve keylatchd address.
		addr := "127.0.0.1:7890"
		if v := env("KEYLATCH_UI_ADDR"); v != "" {
			addr = v
		}

		// Step 1: check if keylatchd is running.
		pingURL := "http://" + addr + "/health"
		client := &http.Client{Timeout: 800 * time.Millisecond}
		resp, err := client.Get(pingURL) //nolint:noctx // short-timeout probe
		if err != nil {
			// keylatchd not reachable.
			return Status{
				Name:    checkName,
				Section: section,
				OK:      true,
				Warn:    true,
				Detail:  "F3 plaintext retention: keylatchd not running — start keylatchd for heap-monitoring",
				Fix:     "Run `keylatch ui` in the background to enable heap-monitoring checks.",
				Tags:    []string{"daemon", "retention"},
			}
		}
		resp.Body.Close()

		// Step 2: query the retention canary endpoint.
		canaryURL := "http://" + addr + "/v1/retention-canary"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, canaryURL, nil)
		if err != nil {
			return Status{
				Name:    checkName,
				Section: section,
				OK:      true,
				Warn:    true,
				Detail:  "F3 plaintext retention: could not build canary request — keylatchd may need upgrade",
				Fix:     "Upgrade keylatchd to a version that supports /v1/retention-canary.",
				Tags:    []string{"daemon", "retention"},
			}
		}
		canaryResp, err := client.Do(req)
		if err != nil || canaryResp.StatusCode == http.StatusNotFound {
			// Endpoint not present — old keylatchd without T-12-03 support.
			if canaryResp != nil {
				canaryResp.Body.Close()
			}
			return Status{
				Name:    checkName,
				Section: section,
				OK:      true,
				Warn:    true,
				Detail:  "F3 plaintext retention: /v1/retention-canary not available — upgrade keylatchd",
				Fix:     "Upgrade keylatchd to a version that supports the retention-canary endpoint.",
				Tags:    []string{"daemon", "retention"},
			}
		}
		defer canaryResp.Body.Close()

		// Parse response.
		var result struct {
			CanaryPresent bool   `json:"canary_present"`
			Detail        string `json:"detail,omitempty"`
		}
		if err := json.NewDecoder(canaryResp.Body).Decode(&result); err != nil {
			return Status{
				Name:    checkName,
				Section: section,
				OK:      true,
				Warn:    true,
				Detail:  "F3 plaintext retention: could not parse canary response",
				Tags:    []string{"daemon", "retention"},
			}
		}

		if result.CanaryPresent {
			return Status{
				Name:    checkName,
				Section: section,
				OK:      false,
				Detail:  "F3 plaintext retention: canary still present in keylatchd memory — memory leak",
				Fix:     "keylatchd memory leak detected: upgrade or restart keylatchd.",
				Tags:    []string{"daemon", "retention", "security"},
			}
		}

		return Status{
			Name:    checkName,
			Section: section,
			OK:      true,
			Detail:  "F3 plaintext retention: cleared after run",
			Tags:    []string{"daemon", "retention"},
		}
	}
}

// checkBootstrapKeyring — F1
//
// Verifies that ~/.keylatch/keyring/keyring.json (or the env-overridden path)
// exists and is non-empty. A missing or empty keyring means keylatch has never
// been bootstrapped.
func checkBootstrapKeyring(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		p := paths.KeyringPath(env)
		info, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				return Status{
					Name:    "F1 bootstrap.keyring",
					Section: "environment",
					OK:      false,
					Detail:  fmt.Sprintf("keyring not found at %s — keylatch not bootstrapped", p),
					Fix:     "Run `keylatch bootstrap` to initialise the keyring.",
					Tags:    []string{"bootstrap", "keyring"},
				}
			}
			return Status{
				Name:    "F1 bootstrap.keyring",
				Section: "environment",
				OK:      false,
				Detail:  fmt.Sprintf("could not stat keyring at %s: %v", p, err),
				Tags:    []string{"bootstrap", "keyring"},
			}
		}
		if info.Size() == 0 {
			return Status{
				Name:    "F1 bootstrap.keyring",
				Section: "environment",
				OK:      false,
				Detail:  fmt.Sprintf("keyring file is empty at %s", p),
				Fix:     "Run `keylatch bootstrap` to reinitialise the keyring.",
				Tags:    []string{"bootstrap", "keyring"},
			}
		}
		return Status{
			Name:    "F1 bootstrap.keyring",
			Section: "environment",
			OK:      true,
			Detail:  fmt.Sprintf("keyring present at %s (%d bytes)", p, info.Size()),
			Tags:    []string{"bootstrap", "keyring"},
		}
	}
}

// checkBootstrapConfig — F2
//
// Verifies that ~/.keylatch/config.json (or the env-overridden path) exists
// and can be parsed.
func checkBootstrapConfig(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		p := paths.Config(env)
		data, err := os.ReadFile(p) //nolint:gosec // read own config file
		if err != nil {
			if os.IsNotExist(err) {
				return Status{
					Name:    "F2 bootstrap.config",
					Section: "environment",
					OK:      false,
					Detail:  fmt.Sprintf("config not found at %s — keylatch not bootstrapped", p),
					Fix:     "Run `keylatch bootstrap` to create the default configuration.",
					Tags:    []string{"bootstrap", "config"},
				}
			}
			return Status{
				Name:    "F2 bootstrap.config",
				Section: "environment",
				OK:      false,
				Detail:  fmt.Sprintf("could not read config at %s: %v", p, err),
				Tags:    []string{"bootstrap", "config"},
			}
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			return Status{
				Name:    "F2 bootstrap.config",
				Section: "environment",
				OK:      false,
				Detail:  fmt.Sprintf("config at %s is not valid JSON: %v", p, err),
				Fix:     "Run `keylatch bootstrap` to recreate the default configuration.",
				Tags:    []string{"bootstrap", "config"},
			}
		}
		return Status{
			Name:    "F2 bootstrap.config",
			Section: "environment",
			OK:      true,
			Detail:  fmt.Sprintf("config present and parseable at %s", p),
			Tags:    []string{"bootstrap", "config"},
		}
	}
}

// checkAgentGuard checks whether the exfiltration guard is installed for at
// least one supported agent. If no agent has the guard installed it emits a
// warning with a remediation hint.
func checkAgentGuard() Check {
	return func(_ context.Context) Status {
		for _, agent := range guard.SupportedAgents {
			ok, err := guard.IsInstalled(agent, guard.InstallOpts{})
			if err == nil && ok {
				return Status{
					Name:    "agent guard",
					Section: "environment",
					OK:      true,
					Detail:  fmt.Sprintf("exfiltration guard installed for agent %q", agent),
					Tags:    []string{"guard"},
				}
			}
		}
		return Status{
			Name:    "agent guard",
			Section: "environment",
			OK:      true,
			Warn:    true,
			Detail:  "No agent exfiltration guard installed — run: keylatch install-guard <agent>",
			Fix:     "keylatch install-guard <agent>",
			Tags:    []string{"guard"},
		}
	}
}

// namedCheck pairs a section label with its check function so that category
// filtering can skip checks before they are executed (W5).
type namedCheck struct {
	section string
	fn      func(ctx context.Context) Status
}

// gatherChecks returns all checks in canonical order as namedCheck values.
// The section field enables pre-execution category filtering.
func gatherChecks(env llmcontext.Lookup, probe kexec.Probe) []namedCheck {
	return []namedCheck{
		// F1/F2: bootstrap presence checks — run first so other checks have context.
		{"environment", checkBootstrapKeyring(env)},
		{"environment", checkBootstrapConfig(env)},
		{"environment", checkVersionBinary()},
		{"environment", checkPlatform()},
		{"environment", checkLLMSession(env)},
		{"environment", checkPathsConfig(env)},
		{"environment", checkPathsVault(env)},
		{"environment", checkPathsAudit(env)},
		// EPIC-17: operating mode check.
		{"environment", checkOperatingMode(env)},
		{"backends", checkBackendSelected(env)},
		{"backends", checkBackendKeychain(probe)},
		{"backends", checkBackendOP(env, probe)},
		{"backends", checkBackendOPAuth(env, probe)},
		{"backends", checkBackendBW(probe)},
		{"backends", checkBackendBWSession(env, probe)},
		{"backends", checkBackendProtonPass(probe)},
		{"backends", checkBackendKeeper(probe)},
		{"backends", checkBackendLastPass(probe)},
		{"backends", checkBackendFile(env)},
		{"daemon", checkExternalDocker(env, probe)},
		{"daemon", checkExternalSOPS(probe)},
		// EPIC-10: external PM CLI checks (op, aws, vault) — skipped when no
		// --provider-ref connections are configured.
		{"external", checkExternalOP(env, probe)},
		{"external", checkExternalAWSSM(env, probe)},
		{"external", checkExternalHashiVault(env, probe)},
		{"providers", checkACLKeychainUnlock()},
		{"environment", checkHookPreToolUse(env)},
		{"environment", checkCosignInstalled(probe)},
		// P1.8: soft checks.
		{"providers", checkNoConnections(env)},
		{"daemon", checkGatewayRunning(env)},
		// T-12-03: F3 — plaintext retention after run.
		{"daemon", checkPlaintextRetention(env)},
		// EPIC-33: I3 — integration markers.
		{"environment", checkIntegrationMarkers()},
		// agent guard — warn if no exfiltration guard is installed for any agent.
		{"environment", checkAgentGuard()},
	}
}
