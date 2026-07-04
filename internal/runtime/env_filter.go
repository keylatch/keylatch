// Package runtime — env_filter.go strips KEYLATCH_* env vars from child process
// environments, retaining only the explicitly injected vars.
//
// Every runtime driver wires FilterChildEnv at the
// exec.Cmd.Env = ... site so that no KEYLATCH_* configuration var leaks to the
// child process. Drivers in gateway modes re-inject the two gateway vars
// (KEYLATCH_GATEWAY_TOKEN, KEYLATCH_GATEWAY_URL) explicitly after filtering.
//
// Filter() is the unified entry point that wraps
// FilterChildEnv / CleanBaseEnv, emits child_env.filter / child_env.clean audit
// events, and accepts a FilterOpts struct for structured configuration.
//
// Security rationale: a child process that can run `env | grep KEYLATCH` learns
// the vault path (KEYLATCH_DATA_DIR), backend type (KEYLATCH_BACKEND), and
// historically the passphrase env var. Even with AEAD ciphertext on disk, leaking
// the vault path is reconnaissance. FilterChildEnv closes this channel.
package runtime

import (
	"context"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
)

// FilterOpts controls how Filter() processes a child process environment.
//
// Replaces the per-driver ad-hoc construction pattern with
// a single options struct that is straightforward to extend without changing call sites.
type FilterOpts struct {
	// Mode identifies the runtime mode (gateway_typed, gateway_sdk, direct_brokered,
	// gateway_proxy). It is stored in audit events for attribution.
	Mode RuntimeMode
	// GatewayToken is the KEYLATCH_GATEWAY_TOKEN value to re-inject in gateway modes.
	// Empty string means do not inject this var.
	GatewayToken string
	// GatewayURL is the KEYLATCH_GATEWAY_URL value to re-inject in gateway modes.
	// Empty string means do not inject this var.
	GatewayURL string
	// CleanEnv, when true, applies CleanBaseEnv (minimal allowlist) instead of
	// FilterChildEnv (strip-KEYLATCH_*-only). --clean-env flag.
	CleanEnv bool
	// Extras lists additional variable names to preserve when CleanEnv is true.
	// These names are passed through to CleanBaseEnv and are included in the
	// child_env.clean audit event's preserved_vars list.
	Extras []string
}

// Filter applies env-hygiene rules to parent and returns a filtered copy.
//
// Behaviour depends on opts.CleanEnv:
//   - false (default): FilterChildEnv strips all KEYLATCH_* vars not in the
//     keep list, then re-injects GatewayToken / GatewayURL when non-empty.
//   - true (--clean-env): CleanBaseEnv retains only the minimal safe allowlist
//     (PATH, HOME, USER, …, LC_*) plus opts.Extras. GatewayToken / GatewayURL
//     are still re-injected when non-empty.
//
// Audit events (emitted only when an audit.Emitter is present in ctx):
//   - child_env.filter — stripped variable names (not values). Always emitted.
//   - child_env.clean  — preserved variable names + stripped count. Only when CleanEnv=true.
//
// Filter does NOT modify the input slice.
func Filter(ctx context.Context, parent []string, opts FilterOpts) []string {
	var out []string
	var strippedNames []string

	if opts.CleanEnv {
		// CleanBaseEnv returns the minimal allowlist subset.
		out = CleanBaseEnv(parent, opts.Extras...)
		// Compute stripped var names for audit (names only, never values).
		outSet := make(map[string]struct{}, len(out))
		for _, e := range out {
			outSet[envKey(e)] = struct{}{}
		}
		for _, e := range parent {
			k := envKey(e)
			if _, kept := outSet[k]; !kept {
				strippedNames = append(strippedNames, k)
			}
		}
		// Re-inject gateway credential vars (these come after CleanBaseEnv so
		// they are not stripped even if not in the base allowlist).
		if opts.GatewayToken != "" {
			out = appendOrReplaceKV(out, "KEYLATCH_GATEWAY_TOKEN", opts.GatewayToken)
		}
		if opts.GatewayURL != "" {
			out = appendOrReplaceKV(out, "KEYLATCH_GATEWAY_URL", opts.GatewayURL)
		}

		// Emit child_env.clean audit event.
		if emitter := audit.EmitterFromCtx(ctx); emitter != nil {
			preservedNames := make([]string, 0, len(out))
			for _, e := range out {
				preservedNames = append(preservedNames, envKey(e))
			}
			_ = emitter.Emit(ctx, audit.Event{
				Action:  audit.ActionCleanEnv,
				Outcome: audit.OutcomeOK,
				Extra: map[string]any{
					"runtime":        string(opts.Mode),
					"preserved_vars": preservedNames,
					"stripped_count": len(strippedNames),
				},
			})
		}
	} else {
		// Determine which KEYLATCH_* vars to re-inject (keep list).
		var keep []string
		if opts.GatewayToken != "" {
			keep = append(keep, "KEYLATCH_GATEWAY_TOKEN")
		}
		if opts.GatewayURL != "" {
			keep = append(keep, "KEYLATCH_GATEWAY_URL")
		}
		// FilterChildEnv strips all KEYLATCH_* vars not in keep.
		out = FilterChildEnv(parent, keep...)
		// Compute stripped KEYLATCH_* names for audit.
		for _, e := range parent {
			k := envKey(e)
			if strings.HasPrefix(k, "KEYLATCH_") {
				inKeep := false
				for _, kept := range keep {
					if k == kept {
						inKeep = true
						break
					}
				}
				if !inKeep {
					strippedNames = append(strippedNames, k)
				}
			}
		}
		// Re-inject gateway credential vars after filtering.
		if opts.GatewayToken != "" {
			out = appendOrReplaceKV(out, "KEYLATCH_GATEWAY_TOKEN", opts.GatewayToken)
		}
		if opts.GatewayURL != "" {
			out = appendOrReplaceKV(out, "KEYLATCH_GATEWAY_URL", opts.GatewayURL)
		}
	}

	// Emit child_env.filter audit event (always, for both clean and non-clean).
	if emitter := audit.EmitterFromCtx(ctx); emitter != nil {
		_ = emitter.Emit(ctx, audit.Event{
			Action:  audit.ActionChildEnvFilter,
			Outcome: audit.OutcomeOK,
			Extra: map[string]any{
				"runtime":       string(opts.Mode),
				"stripped_vars": strippedNames,
				"clean_env":     opts.CleanEnv,
			},
		})
	}

	return out
}

// appendOrReplaceKV returns env with key=value set.
// If key is already present, the same underlying array is modified in-place.
// Callers must not rely on the input slice remaining unchanged after a replacement.
//
// This is a package-private variant of the runner.appendOrReplace helper, kept
// here to avoid an import cycle (runner imports runtime).
func appendOrReplaceKV(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = key + "=" + value
			return env
		}
	}
	return append(env, key+"="+value)
}

// FilterChildEnv returns a copy of env with every KEYLATCH_* variable removed,
// except those explicitly listed in keep.
//
// The keep list should contain only the vars that the driver explicitly re-injects
// (e.g. "KEYLATCH_GATEWAY_TOKEN", "KEYLATCH_GATEWAY_URL"). It is intentionally
// short — the policy is strip-by-default.
//
// FilterChildEnv does NOT modify the input slice.
func FilterChildEnv(env []string, keep ...string) []string {
	keepSet := make(map[string]struct{}, len(keep))
	for _, k := range keep {
		keepSet[k] = struct{}{}
	}

	out := make([]string, 0, len(env))
	for _, e := range env {
		key := envKey(e)
		if strings.HasPrefix(key, "KEYLATCH_") {
			if _, ok := keepSet[key]; !ok {
				continue // strip
			}
		}
		out = append(out, e)
	}
	return out
}

// envKey returns the variable name portion of an "KEY=VALUE" string.
// If there is no '=', the whole string is returned as the key.
func envKey(e string) string {
	for i := 0; i < len(e); i++ {
		if e[i] == '=' {
			return e[:i]
		}
	}
	return e
}

// cleanBaseVars is the allowlist for CleanBaseEnv: these variables are
// preserved from the parent environment. Every other var (including all
// KEYLATCH_* vars) is stripped. Drivers re-inject credential vars explicitly.
//
// The list covers the vars required for most CLI tools to function
// correctly without leaking any secrets or keylatch configuration.
var cleanBaseVars = map[string]bool{
	"PATH":            true,
	"HOME":            true,
	"USER":            true,
	"LOGNAME":         true,
	"SHELL":           true,
	"TERM":            true,
	"TERM_PROGRAM":    true,
	"COLORTERM":       true,
	"LANG":            true,
	"TMPDIR":          true,
	"TMP":             true,
	"TEMP":            true,
	"XDG_RUNTIME_DIR": true,
}

// CleanBaseEnv returns a minimal environment suitable for clean child-process
// execution (--clean-env flag).
//
// The returned slice contains only:
//   - Variables from the cleanBaseVars allowlist (PATH, HOME, USER, …)
//   - Variables whose names begin with "LC_" (locale categories)
//   - Variables from the extra list (caller-controlled preservation)
//
// All KEYLATCH_* vars and all other vars are stripped. Drivers must
// append credential vars explicitly after calling CleanBaseEnv.
//
// CleanBaseEnv does NOT modify the input slice.
func CleanBaseEnv(env []string, extra ...string) []string {
	extraSet := make(map[string]struct{}, len(extra))
	for _, k := range extra {
		extraSet[k] = struct{}{}
	}

	out := make([]string, 0, 20) // typical clean env is small
	for _, e := range env {
		key := envKey(e)
		if cleanBaseVars[key] {
			out = append(out, e)
			continue
		}
		if strings.HasPrefix(key, "LC_") {
			out = append(out, e)
			continue
		}
		if _, ok := extraSet[key]; ok {
			out = append(out, e)
			continue
		}
		// All other vars (including KEYLATCH_*) are stripped.
	}
	return out
}
