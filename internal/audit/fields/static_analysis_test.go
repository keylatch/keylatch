// static_analysis_test.go — T6-07
// Walks all Go source files and checks that any literal string keys in
// audit.Event{Extra: map[string]any{...}} struct field initializers are
// present in the SafeLogFields allowlist for at least one action (S5-2).
//
// This is a best-effort static check over literal map keys inside `Extra:`
// field values only. Computed string keys and keys starting with "_" are
// exempt from the check.
package fields_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit/fields"
)

// TestNoUnallowlistedExtraKeys walks Go source files under the repo root and
// verifies that any literal string keys in `Extra: map[string]any{...}` struct
// field initializers are present in the SafeLogFields allowlist (S5-2).
func TestNoUnallowlistedExtraKeys(t *testing.T) {
	root, err := findModuleRoot()
	if err != nil {
		t.Skipf("cannot find module root: %v", err)
	}

	// Collect all allowed keys across all actions by calling Redact with
	// test values and recording which pass through unchanged.
	allAllowedKeys := map[string]bool{}
	for _, action := range fields.AllActions() {
		testExtra := map[string]any{
			"version": 1, "backend": "file", "key_term": 1, "prefix": "x",
			"count": 1, "result": "ok", "new_term": 1, "old_term": 1,
			"algorithm": "xchacha20-poly1305", "kek_type": "passphrase",
			"old_kek_type": "passphrase", "new_kek_type": "keychain",
			"term": 1, "token_type": "jwt", "ttl": 300, "policy_id": "p1",
			"recipient_hmac": "abc", "delegate_type": "viewer",
			// Phase 13 broker keys (FIND2-012 — actor/session IDs HMAC-hashed).
			"provider": "openai", "exchange_strategy": "oauth_refresh",
			"actor_hmac": "aabbcc", "session_id_hmac": "ddeeff",
			"namespace": "default", "capability": "chat",
			"ttl_seconds": int64(3600), "cache_age_seconds": int64(60),
			"ttl_remaining_seconds": int64(3540), "scopes_count": 0,
			// broker.direct_run_* keys.
			"sandbox_profile": "default", "masking_profile_applied": "basic",
			"budget_remaining": "50/100", "ttl_seconds_used": int64(10),
			"allowed_hosts_count": 3,
			"connection":          "tcp", "runtime_requested": "direct_run",
			"llm_session_signal": true, "blocked_by": "llm_session_gate",
			// gateway_call keys (Epic 07 — T04 proxy deny audit).
			"reason": "ssrf_denied", "host": "api.example.com", "error": "capability_mismatch",
			// proxy lifecycle keys (Epic 18 — proxy.started / proxy.stopped).
			"port": 8888, "pid": os.Getpid(),
			// T-13-07: audit_rotate cross-file chain continuity keys.
			"rotated_to": "/path/to/log.1", "rotated_from": "/path/to/log.1",
			"prev_file_hmac": "abcdef0123456789",
			// EPIC-09 child-env hygiene keys (T-09-01).
			"runtime":       "gateway_typed",
			"stripped_vars": "KEYLATCH_BACKEND", "clean_env": false,
			"preserved_vars": "PATH,HOME", "stripped_count": 5,
			// EPIC-24 sandbox action keys.
			"executable":        "/usr/bin/myapp",
			"executable_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
			"expected":          "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000",
			"actual":            "bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111bbbb1111",
			"denied_paths":      "/home/user/.keylatch",
			// Phase 13 broker dry-run and token revocation keys.
			"command":                       "node x.js",
			"policy_decision":               "allow",
			"token_id":                      "tok_abc123",
			"timestamp":                     "2026-05-18T00:00:00Z",
			"provider_revocation_attempted": false,
			"provider_revocation_succeeded": false,
		}
		salt := []byte("allowlist-discovery")
		out := fields.Redact(salt, action, testExtra)
		for k, outV := range out {
			if inV, ok := testExtra[k]; ok && outV == inV {
				allAllowedKeys[k] = true
			}
		}
	}

	var violations []string

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == "vendor" || base == "testdata" || base == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil
		}

		// Walk the AST looking for KeyValueExpr where Key.Name == "Extra"
		// and Value is a map[string]any composite literal.
		ast.Inspect(f, func(n ast.Node) bool {
			kve, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			keyIdent, ok := kve.Key.(*ast.Ident)
			if !ok || keyIdent.Name != "Extra" {
				return true
			}
			cl, ok := kve.Value.(*ast.CompositeLit)
			if !ok {
				return true
			}
			mt, ok := cl.Type.(*ast.MapType)
			if !ok {
				return true
			}
			if ident, ok := mt.Key.(*ast.Ident); !ok || ident.Name != "string" {
				return true
			}

			for _, elt := range cl.Elts {
				kvElt, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				lit, ok := kvElt.Key.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				key := strings.Trim(lit.Value, `"'`)
				// Keys starting with "_" are test/debug keys that are intentionally
				// not in the allowlist; Redact will HMAC them.
				if strings.HasPrefix(key, "_") {
					continue
				}
				if !allAllowedKeys[key] {
					pos := fset.Position(kvElt.Pos())
					violations = append(violations,
						pos.String()+": Extra key \""+key+"\" not in SafeLogFields allowlist (S5-2)")
				}
			}
			return true
		})
		return nil
	})

	for _, v := range violations {
		t.Errorf("%s", v)
	}
}

// findModuleRoot walks up from the current working directory to find go.mod.
func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
