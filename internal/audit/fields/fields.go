// Package fields implements the SafeLogFields allowlist that enforces
// audit entry value-freedom.
//
// Only explicitly listed keys for each Action are passed through to the audit
// log in plaintext. All other keys are replaced with their HMAC'd form via
// the Redact function.
package fields

import (
	"fmt"

	"github.com/keylatch/keylatch/internal/audit/hmac"
)

// safeLogFieldsType maps Action strings to their allowed extra field keys.
// Only keys present in this allowlist are passed through by Redact; all other
// keys have their values replaced with HMAC(salt, value).
//
// The "audit" package Action type is imported indirectly to avoid a circular
// import. We use string keys here and accept audit.Action at the Redact boundary.
var safeLogFields = map[string][]string{
	"write":        {"version", "backend", "key_term"},
	"read":         {"version", "backend", "key_term"},
	"delete":       {"version", "backend"},
	"list":         {"prefix", "count"},
	"decrypt":      {"version", "backend", "key_term"},
	"encrypt":      {"version", "backend", "key_term"},
	"revoke":       {"version"},
	"rotate":       {"new_term", "old_term"},
	"keyring_init": {"algorithm", "kek_type"},
	"kek_rotate":   {"old_kek_type", "new_kek_type"},
	"term_destroy": {"term"},
	// rotated_to/rotated_from are file paths (no credential content).
	// prev_file_hmac is a chain MAC value needed for cross-file chain verification.
	"audit_rotate": {"rotated_to", "rotated_from", "prev_file_hmac"},
	"audit_verify": {"result"},
	"audit_read":   {},
	// forward-compat
	"policy_check": {"policy_id", "result"},
	"token_issue":  {"token_type", "ttl"},
	"token_revoke": {"token_type"},
	// forward-compat
	"share":    {"recipient_hmac"},
	"unshare":  {"recipient_hmac"},
	"delegate": {"delegate_type"},
	// Gateway proxy actions.
	"gateway_call": {"reason", "host", "error", "capability"},
	// Proxy lifecycle actions.
	"proxy.started": {"port", "pid"},
	"proxy.stopped": {"pid", "reason"},
	// broker actions — all actor/session IDs are HMAC-hashed.
	"broker.exchange": {
		"provider", "exchange_strategy", "actor_hmac", "session_id_hmac",
		"namespace", "capability", "ttl_seconds", "scopes_count",
	},
	"broker.cache_hit": {
		"provider", "actor_hmac", "session_id_hmac",
		"capability", "cache_age_seconds", "ttl_remaining_seconds",
	},
	"broker.direct_run_credential_access": {
		"provider", "actor_hmac", "capability",
		"sandbox_profile", "masking_profile_applied",
		"budget_remaining", "ttl_seconds_used", "allowed_hosts_count",
	},
	"broker.direct_run_blocked": {
		"actor_hmac", "connection", "capability",
		"runtime_requested", "llm_session_signal", "blocked_by",
	},
	// child-env hygiene actions.
	// stripped_vars: list of KEYLATCH_* var names removed (no values).
	// In CleanEnv mode: contains ALL var names not in the allowlist (every non-
	// allowlisted variable from parent, regardless of prefix).
	// In non-CleanEnv mode: contains only the KEYLATCH_* var names that were
	// stripped (non-KEYLATCH_* vars are never touched and therefore not listed).
	// clean_env: boolean; true when --clean-env was applied.
	"child_env.filter": {"runtime", "stripped_vars", "clean_env"},
	// preserved_vars: list of var names kept in the minimal allowlist.
	// stripped_count: integer count of stripped vars.
	"child_env.clean": {"runtime", "preserved_vars", "stripped_count"},

	// sandbox actions.
	// executable: the path of the binary being sandboxed (path only, never its value).
	// executable_sha256: SHA-256 hex digest of the executable (value-free — no credentials).
	"sandbox.launched": {"provider", "runtime", "executable", "executable_sha256"},
	// expected/actual: SHA-256 hashes of the executable (not credential values).
	// reason: short string describing the refusal (e.g. "hash-mismatch").
	"sandbox.launch_refused": {"provider", "runtime", "expected", "actual", "reason"},
	// denied_paths: list of filesystem paths denied in the sandbox (no values).
	"sandbox.deny_applied": {"provider", "runtime", "denied_paths"},

	// operating-mode actions.
	// ActionCanaryInjected — provider slug and session_id_hmac (no canary token value).
	"canary.injected": {"provider", "session_id_hmac"},

	// broker dry-run action.
	// command: the binary/subcommand name requested (no credential content).
	// policy_decision: "allow" or "deny" string — no secret content.
	"broker.dry_run_requested": {
		"provider", "command", "scopes_count", "policy_decision",
	},
	// broker token revocation action.
	// token_id: opaque token identifier used for audit correlation (not a credential value).
	// timestamp: UTC RFC3339 time of revocation.
	// provider_revocation_attempted / provider_revocation_succeeded: boolean metadata.
	"broker.token_revoked": {
		"provider", "actor_hmac", "token_id", "timestamp",
		"provider_revocation_attempted", "provider_revocation_succeeded",
	},
}

// Redact filters extra map keys against the SafeLogFields allowlist for action.
//
// Keys present in SafeLogFields[action] are copied as-is.
// All other keys have their values replaced with HMAC(salt, fmt.Sprint(value)).
//
// If extra is nil, returns nil.
func Redact(salt []byte, action string, extra map[string]any) map[string]any {
	if extra == nil {
		return nil
	}
	allowed := make(map[string]bool)
	if keys, ok := safeLogFields[action]; ok {
		for _, k := range keys {
			allowed[k] = true
		}
	}

	out := make(map[string]any, len(extra))
	for k, v := range extra {
		if allowed[k] {
			out[k] = v
		} else {
			// Replace with HMAC of the value — never the value itself.
			out[k] = hmac.Of(salt, []byte(fmt.Sprint(v)))
		}
	}
	return out
}

// AllActions returns the list of all Action constants that must have SafeLogFields entries.
// Used by the init() completeness check and by tests.
func AllActions() []string {
	return []string{
		"write", "read", "delete", "list", "decrypt", "encrypt",
		"revoke", "rotate", "keyring_init", "kek_rotate", "term_destroy",
		"audit_rotate", "audit_verify", "audit_read",
		"policy_check", "token_issue", "token_revoke",
		"share", "unshare", "delegate",
		// gateway_proxy proxy deny action.
		"gateway_call",
		// Proxy lifecycle actions.
		"proxy.started", "proxy.stopped",
		// broker actions.
		"broker.exchange", "broker.cache_hit",
		"broker.direct_run_credential_access", "broker.direct_run_blocked",
		// child-env hygiene actions.
		"child_env.filter", "child_env.clean",
		// sandbox actions.
		"sandbox.launched", "sandbox.launch_refused", "sandbox.deny_applied",
		// canary actions.
		"canary.injected",
		// broker dry-run and token revocation actions.
		"broker.dry_run_requested", "broker.token_revoked",
	}
}

func init() {
	// Compile-time completeness check: panic if any Action is missing from
	// the allowlist. This fires on package initialization.
	for _, action := range AllActions() {
		if _, ok := safeLogFields[action]; !ok {
			panic(fmt.Sprintf("audit/fields: Action %q is missing from SafeLogFields", action))
		}
	}
}
