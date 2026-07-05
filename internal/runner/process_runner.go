// Package runner process_runner.go implements the real ProcessRunner that
// injects credentials from a backend into a subprocess environment.
package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	internalexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/store"
)

// redactingWriter wraps an io.Writer and replaces any byte sequence matching
// one of patterns with the literal string "****" before forwarding to w.
// This prevents credential values from appearing in subprocess output even
// when the subprocess prints its own environment (e.g. `env`, debug logging).
type redactingWriter struct {
	w        io.Writer
	patterns []*regexp.Regexp
}

func (r *redactingWriter) Write(p []byte) (int, error) {
	out := p
	for _, re := range r.patterns {
		out = re.ReplaceAll(out, []byte("****"))
	}
	// Report the original length to satisfy callers that check n == len(p).
	n, err := r.w.Write(out)
	if err != nil {
		return n, err
	}
	return len(p), nil
}

// URIResolver is the interface used by ProcessRunner to resolve external-store
// URI references (op://, aws-sm://, hashivault://) into plaintext bytes.
type URIResolver interface {
	Resolve(ctx context.Context, ref string) ([]byte, error)
}

// ProcessRunner is the production implementation of Runner. It reads
// credentials from the backend and injects them as environment variables
// into a subprocess.
//
// Stdout and Stderr default to os.Stdout and os.Stderr when nil, which is the
// correct behaviour for production use. Tests may set these to a bytes.Buffer
// to capture subprocess output without streaming to the terminal.
//
// ExecRunner is the CommandRunner used to invoke external CLI tools when
// resolving provider-ref URIs (e.g. op://, aws-sm://, hashivault://). When
// nil, internalexec.DefaultRunner is used. Tests may inject a mock runner.
//
// Resolver, if non-nil, overrides the default store.Resolver built from
// ExecRunner. Tests may inject a fully-configured resolver (e.g. with
// WithBinOverride) to avoid PATH lookups.
type ProcessRunner struct {
	Backend    backend.Backend
	Stdout     io.Writer
	Stderr     io.Writer
	ExecRunner internalexec.CommandRunner
	Resolver   URIResolver
}

// Compile-time assertion: ProcessRunner must satisfy the Runner interface.
var _ Runner = ProcessRunner{}

// Run implements Runner for ProcessRunner.
//
// Steps:
//  1. Check conn.AllowedCommandPrefixes — deny if no prefix matches.
//  2. For each InjectionRule on the template, call Backend.Get to read the credential.
//  3. Build the subprocess env: os.Environ() plus injected vars.
//  4. Execute the command, streaming stdin/stdout/stderr.
//  5. Zero all credential bytes on return.
//  6. Return RunReceipt with the subprocess exit code.
//
// Returns ErrCommandNotAllowed when the command is not in the allowlist.
// Returns backend.ErrNotFound (wrapped) if a credential is absent.
func (p ProcessRunner) Run(ctx context.Context, conn Connection, command []string, opts RunOptions) (Receipt, error) {
	// Step 1: Allowlist check against command[0] (the executable).
	// Entries like "node " are trimmed to their bare binary name "node".
	// Matching rules:
	//   - Exact match:   exe == allowed              (e.g. "node" matches "node")
	//   - Dot-suffix:    exe starts with allowed+"." (e.g. "python3.12" matches "python3")
	//   - Path-suffix:   exe starts with allowed+"/" (e.g. "python3/bin" matches "python3")
	// HasPrefix without the suffix guard is intentionally NOT used: it would allow
	// "node_modules/.bin/evil" to match the "node" entry, bypassing the allowlist.
	if len(command) == 0 {
		return Receipt{}, fmt.Errorf("runner: empty command")
	}
	if len(conn.AllowedCommandPrefixes) == 0 {
		return Receipt{}, ErrCommandNotAllowed
	}
	exe := command[0]
	matched := false
	for _, prefix := range conn.AllowedCommandPrefixes {
		trimmed := strings.TrimRight(prefix, " ")
		if exe == trimmed ||
			(strings.HasPrefix(exe, trimmed) && len(exe) > len(trimmed) && (exe[len(trimmed)] == '.' || exe[len(trimmed)] == '/')) {
			matched = true
			break
		}
	}
	if !matched {
		return Receipt{}, ErrCommandNotAllowed
	}

	// Step 2: fetch credentials for each InjectionRule.
	// We store the credential bytes so we can zero them after the subprocess exits.
	type credEntry struct {
		envVar string
		value  []byte
	}
	creds := make([]credEntry, 0)
	defer func() {
		for i := range creds {
			for j := range creds[i].value {
				creds[i].value[j] = 0
			}
		}
	}()

	// Look up the provider template to get InjectionRules.
	tmpl, err := registry.Get(conn.Name)
	if err != nil {
		// If the provider is not registered, we cannot inject credentials.
		return Receipt{}, fmt.Errorf("runner: provider %q not registered: %w", conn.Name, err)
	}

	for _, rule := range tmpl.InjectionRules {
		// Build the canonical storage path: namespace/category/provider/field.
		category := tmpl.Category
		if category == "" {
			category = "ai"
		}
		storagePath := secretFieldLookupPath("default", category, conn.Name, rule.Source)
		val, _, err := p.Backend.Get(ctx, storagePath)
		if err != nil {
			if errors.Is(err, backend.ErrNotFound) {
				return Receipt{}, fmt.Errorf("runner: credential %q not found for connection %q: %w",
					rule.Source, conn.Name, backend.ErrNotFound)
			}
			return Receipt{}, fmt.Errorf("runner: read credential %q: %w", rule.Source, err)
		}
		// Resolve external-store URI references.
		// This runs after the LLM guard (GuardLLMSession) which executes at the
		// CLI layer before the runner is invoked.
		if store.IsProviderRefURI(val) {
			resolver := p.uriResolver()
			resolved, resolveErr := resolver.Resolve(ctx, string(val))
			if resolveErr != nil {
				return Receipt{}, fmt.Errorf("runner: resolve external ref for %q: %w", rule.Source, resolveErr)
			}
			val = resolved
		}
		creds = append(creds, credEntry{envVar: rule.EnvVar, value: val})
	}

	// Step 3: build subprocess env.
	env := os.Environ()
	for _, c := range creds {
		env = append(env, c.envVar+"="+string(c.value))
	}
	// Merge any extra env from opts.
	for k, v := range opts.Env {
		env = append(env, k+"="+v)
	}

	// Step 4: execute command.
	// Compile redaction patterns from the provider template so that any
	// credential values printed by the subprocess (e.g. `env`, debug output)
	// are replaced with "****" before reaching the terminal.
	var redactPatterns []*regexp.Regexp
	for _, rule := range tmpl.Redaction {
		if re, err := regexp.Compile(rule.Pattern); err == nil {
			redactPatterns = append(redactPatterns, re)
		}
	}
	stdout := p.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := p.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	if len(redactPatterns) > 0 {
		stdout = &redactingWriter{w: stdout, patterns: redactPatterns}
		stderr = &redactingWriter{w: stderr, patterns: redactPatterns}
	}
	//nolint:gosec // G204: command is user-supplied and allowlist-checked above.
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Env = env
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	} else {
		cmd.Stdin = os.Stdin
	}

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return Receipt{ExitCode: exitErr.ExitCode()}, nil
		}
		return Receipt{}, fmt.Errorf("runner: exec: %w", err)
	}

	// Step 5: zeroing is handled in defer above.
	return Receipt{ExitCode: 0}, nil
}

// uriResolver returns the URIResolver to use for external-store references.
// Uses p.Resolver when set (test injection), otherwise builds a default
// store.Resolver using p.ExecRunner (or internalexec.DefaultRunner).
func (p ProcessRunner) uriResolver() URIResolver {
	if p.Resolver != nil {
		return p.Resolver
	}
	execRunner := p.ExecRunner
	if execRunner == nil {
		execRunner = internalexec.DefaultRunner
	}
	return store.NewResolver(execRunner)
}

// secretFieldLookupPath returns the canonical vault path for a credential field.
// Canonical format: namespace/category/provider/field.
// No backward-compat read from "default/connections/..." — v1.0.0 has no existing users.
func secretFieldLookupPath(namespace, category, provider, field string) string {
	if category == "" {
		category = "ai"
	}
	return fmt.Sprintf("%s/%s/%s/%s", namespace, category, provider, field)
}
