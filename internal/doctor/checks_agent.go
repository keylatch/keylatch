package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/bw"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/manifest"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy"
)

// claudeConfigDirs returns every directory Claude Code reads settings from
// that exists on this machine: $CLAUDE_CONFIG_DIR and ~/.claude.
func claudeConfigDirs(env llmcontext.Lookup) []string {
	var candidates []string
	if d := env("CLAUDE_CONFIG_DIR"); d != "" {
		candidates = append(candidates, d)
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".claude"))
	}
	seen := map[string]bool{}
	var dirs []string
	for _, d := range candidates {
		d = filepath.Clean(d)
		if seen[d] {
			continue
		}
		seen[d] = true
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// guardHook is one PreToolUse command found in a Claude Code settings file.
type guardHook struct {
	matcher string
	command string
	// script is true for the shell script guard of earlier versions.
	script bool
}

const goGuardSuffix = " guard hook --harness claude-code"

// guardBinary returns the Keylatch binary a current guard command runs.
func guardBinary(command string) string {
	return strings.Trim(strings.TrimSuffix(command, goGuardSuffix), `"`)
}

// claudeGuardHooks returns the PreToolUse hooks in dir whose command is the
// Keylatch guard, current or the script of an earlier version.
func claudeGuardHooks(dir string) ([]guardHook, error) {
	data, err := os.ReadFile(filepath.Join(dir, "settings.json")) //nolint:gosec // G304: the user's own Claude Code settings
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var settings struct {
		Hooks struct {
			PreToolUse []struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("settings.json is not valid JSON: %w", err)
	}
	var found []guardHook
	for _, group := range settings.Hooks.PreToolUse {
		for _, h := range group.Hooks {
			switch {
			case strings.HasSuffix(h.Command, goGuardSuffix):
				found = append(found, guardHook{matcher: group.Matcher, command: h.Command})
			case strings.Contains(filepath.Base(h.Command), "block-keylatch-exfiltration"):
				found = append(found, guardHook{matcher: group.Matcher, command: h.Command, script: true})
			}
		}
	}
	return found, nil
}

// checkClaudeGuardInstalled fails when a Claude Code configuration directory
// exists without the Keylatch guard hook. It is the root cause the version and
// matcher checks depend on.
func checkClaudeGuardInstalled(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "guard.installed", Section: "environment", OK: true, Tags: []string{"guard", "claude-code"}}
		dirs := claudeConfigDirs(env)
		if len(dirs) == 0 {
			st.Detail = "no Claude Code configuration directory found"
			return st
		}
		var missing []string
		for _, dir := range dirs {
			hooks, err := claudeGuardHooks(dir)
			if err != nil {
				st.OK = false
				st.Detail = fmt.Sprintf("cannot read the Claude Code settings in %s: %v", dir, err)
				st.Fix = "Repair the settings.json, then run `keylatch install-guard claude-code`."
				return st
			}
			if len(hooks) == 0 {
				missing = append(missing, dir)
			}
		}
		if len(missing) > 0 {
			st.OK = false
			st.Detail = fmt.Sprintf("the exfiltration guard is not installed for Claude Code (%s)", strings.Join(missing, ", "))
			st.Fix = "Run `keylatch install-guard claude-code`."
			return st
		}
		st.Detail = fmt.Sprintf("guard hook installed in %d Claude Code configuration director%s", len(dirs), map[bool]string{true: "y", false: "ies"}[len(dirs) == 1])
		return st
	}
}

// checkClaudeGuardCurrent fails when the installed guard is the shell script of
// an earlier version, or when the Keylatch binary its hook runs is gone.
func checkClaudeGuardCurrent(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "guard.current", Section: "environment", OK: true, Tags: []string{"guard", "claude-code"}}
		for _, dir := range claudeConfigDirs(env) {
			hooks, _ := claudeGuardHooks(dir)
			for _, h := range hooks {
				if h.script {
					st.OK = false
					st.Detail = fmt.Sprintf("the guard in %s is the shell script of an earlier version, which does not parse commands", dir)
					st.Fix = "Run `keylatch install-guard claude-code --upgrade` to replace it."
					return st
				}
				if _, err := os.Stat(guardBinary(h.command)); err != nil {
					st.OK = false
					st.Detail = fmt.Sprintf("the guard hook in %s runs %s, which cannot be found: %v", dir, guardBinary(h.command), err)
					st.Fix = "Run `keylatch install-guard claude-code --upgrade` to point it at the installed binary."
					return st
				}
			}
		}
		st.Detail = "guard hook runs the structured guard in an installed keylatch binary"
		return st
	}
}

// checkClaudeGuardMatcher fails when the guard hook only covers some tools.
// An empty matcher and "*" both select every tool.
func checkClaudeGuardMatcher(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "guard.matcher", Section: "environment", OK: true, Tags: []string{"guard", "claude-code"}}
		for _, dir := range claudeConfigDirs(env) {
			hooks, _ := claudeGuardHooks(dir)
			for _, h := range hooks {
				if h.matcher != "" && h.matcher != "*" {
					st.OK = false
					st.Detail = fmt.Sprintf("the guard hook in %s only covers tools matching %q; every tool must be covered", dir, h.matcher)
					st.Fix = "Set the hook's matcher to \"*\" in Claude Code settings, or run `keylatch install-guard claude-code`."
					return st
				}
			}
		}
		st.Detail = "guard hook matches every tool"
		return st
	}
}

// checkPolicyDefaultDeny fails when there is no policy or the policy would
// allow what no rule names.
func checkPolicyDefaultDeny(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "policy.default_deny", Section: "environment", OK: true, Tags: []string{"policy"}}
		p, err := policy.Load(paths.Policy(env))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			st.OK = false
			st.Detail = "no policy file; nothing restricts which callers may use which connections"
			st.Fix = "Run `keylatch policy init`."
		case err != nil:
			st.OK = false
			st.Detail = fmt.Sprintf("the policy file cannot be read: %v", err)
			st.Fix = "Run `keylatch policy init --force` to replace it with a default-deny policy."
		case !p.DefaultDeny:
			st.OK = false
			st.Detail = "the policy is not default-deny"
			st.Fix = "Run `keylatch policy init --force` to replace it with a default-deny policy."
		default:
			st.Detail = fmt.Sprintf("default-deny policy with %d rule(s)", len(p.Rules))
		}
		return st
	}
}

// backendCredentialVariables are environment variables that hand a backend's
// credentials to every process the shell starts, an agent included.
var backendCredentialVariables = []string{
	"BW_SESSION", "BW_CLIENTSECRET", "BW_PASSWORD",
	"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "OP_SESSION",
	"VAULT_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
	"AZURE_CLIENT_SECRET", "DOPPLER_TOKEN", "INFISICAL_TOKEN",
}

// checkBackendCredentialsInEnvironment warns when backend credentials are
// exported to this process. It reports names only.
func checkBackendCredentialsInEnvironment(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "env.backend_credentials", Section: "environment", OK: true, Tags: []string{"environment", "security"}}
		var present []string
		for _, name := range backendCredentialVariables {
			if env(name) != "" {
				present = append(present, name)
			}
		}
		sort.Strings(present)
		if len(present) == 0 {
			st.Detail = "no backend credentials exported in the environment"
			return st
		}
		st.Warn = true
		st.Detail = "backend credentials are exported to this process and to anything it starts: " + strings.Join(present, ", ")
		st.Fix = "Unset them and start agents from a shell where they are not exported."
		return st
	}
}

// checkLeftoverBWSession fails on a plaintext Bitwarden session file left by an
// earlier version: any process running as the user can unlock the vault with
// it. Sessions are now stored only wrapped by the vault key.
func checkLeftoverBWSession(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "backend.bw_session_file", Section: "environment", OK: true, Tags: []string{"backend", "bw"}}
		if _, err := os.Stat(bw.LegacySessionPath(env)); err != nil {
			st.Detail = "no plaintext Bitwarden session file"
			return st
		}
		st.OK = false
		st.Detail = "a plaintext Bitwarden session file is on disk; any process running as you can unlock the vault with it"
		st.Fix = "Run `keylatch bw lock` to remove it."
		return st
	}
}

// checkAuditChain verifies the audit log's hash chain.
func checkAuditChain(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "audit.chain", Section: "environment", OK: true, Tags: []string{"audit"}}
		salt, err := os.ReadFile(paths.AuditSalt(env)) //nolint:gosec // G304: the configured audit salt
		if err != nil {
			st.Detail = "no audit salt yet; nothing to verify"
			return st
		}
		report, err := audit.VerifyChain(paths.Audit(env), salt, nil)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			st.Detail = "no audit events yet"
		case err != nil:
			st.OK = false
			st.Detail = fmt.Sprintf("the audit log cannot be verified: %v", err)
			st.Fix = "Run `keylatch audit --verify-chain` for the details."
		case report.FirstBadLine != 0:
			st.OK = false
			st.Detail = fmt.Sprintf("the audit chain is broken at line %d: %s", report.FirstBadLine, report.FirstBadReason)
			st.Fix = "Run `keylatch audit --verify-chain` and keep the log as evidence."
		default:
			st.Detail = fmt.Sprintf("audit chain intact (%d events)", report.TotalLines)
		}
		return st
	}
}

// checkBackendTier reports the configured backend's support tier from the
// support manifest.
func checkBackendTier(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "backend.tier", Section: "backends", OK: true, Tags: []string{"backend", "tier"}}
		cfg, err := config.Load(paths.Config(env))
		if err != nil || cfg.Backend == "" {
			st.Detail = "no backend configured yet"
			return st
		}
		name := cfg.Backend
		if canonical, ok := backend.CanonicalName(name); ok {
			name = canonical
		}
		entry, ok := manifest.Current().Lookup(name)
		if !ok || entry.Category != manifest.CategoryManager {
			st.OK = false
			st.Detail = fmt.Sprintf("backend %q is not in the support manifest", cfg.Backend)
			st.Fix = "Run `keylatch backend list` to see the supported backends."
			return st
		}
		st.Detail = fmt.Sprintf("backend %s is %s", name, entry.Status)
		switch entry.Status {
		case manifest.Community, manifest.Deprecated:
			st.Warn = true
			st.Detail += ": " + entry.Note
			st.Fix = "Run `keylatch backend list` to compare the supported backends."
		case manifest.Supported, manifest.Preview:
		default:
			st.OK = false
			st.Fix = "Run `keylatch backend list` to see the supported backends."
		}
		return st
	}
}

// brokerPlatforms lists the platforms that have a broker daemon. None do yet.
func brokerPlatforms() []string { return nil }

// checkInUserMode reports the deployment mode. Without a broker daemon the
// keys are held by the user's own account.
func checkInUserMode() Check {
	return func(_ context.Context) Status {
		st := Status{Name: "mode.deployment", Section: "environment", OK: true, Tags: []string{"mode"}}
		st.Detail = "in-user mode: keys are held by your own account, so protection depends on the agent guard and policy, not on a separate OS user"
		for _, p := range brokerPlatforms() {
			if p == runtime.GOOS {
				st.Warn = true
				st.Fix = "Install the broker service to hold keys under its own OS user."
			}
		}
		return st
	}
}
