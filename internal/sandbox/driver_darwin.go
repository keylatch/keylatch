//go:build darwin

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// RunSandboxed executes m.Executable inside an Apple sandbox-exec(1) sandbox.
//
// Security properties:
// - Executable hash is verified before exec.
// - Keylatch state and every Deny path are denied in the generated .sb profile.
// - Only explicit EnvInject vars are passed via env(1); inherit is false.
// - No shell string construction — argv is a slice.
// - KEYLATCH_* vars are never exposed in sandbox-exec's environment (cmd.Env is set explicitly).
// - A deprecation warning is emitted: sandbox-exec is undocumented and may
// be removed in a future macOS release.
//
// If featureEnabled is false, ErrFeatureFlagRequired is returned.
func RunSandboxed(ctx context.Context, m *SandboxManifest, featureEnabled bool, extraEnv []string, emitter audit.Emitter) error {
	if !featureEnabled {
		return ErrFeatureFlagRequired
	}

	// Emit deprecation warning — sandbox-exec is undocumented on modern macOS (S3).
	const deprecationMsg = "keylatch: sandbox (direct_classic_sandboxed) on macOS uses sandbox-exec(1), " +
		"which is an undocumented Apple facility and may be removed in a future macOS release."
	slog.Warn(deprecationMsg)

	// Verify executable hash.
	if err := VerifyExecHash(m); err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("sandbox: get home dir: %w", err)
	}
	if err := validateBindMountsWithHome(m, home); err != nil {
		return err
	}

	sbProfile, err := generateSbProfile(m)
	if err != nil {
		return fmt.Errorf("sandbox: generate sb profile: %w", err)
	}

	if emitter != nil {
		_ = emitter.Emit(ctx, audit.Event{
			Action:  audit.ActionSandboxDenyApplied,
			Outcome: audit.OutcomeOK,
			Extra: map[string]any{
				"denied_paths": m.Deny,
			},
		})
	}

	// Write .sb profile to a temp file.
	tmpFile, err := os.CreateTemp("", "keylatch-sandbox-*.sb")
	if err != nil {
		return fmt.Errorf("sandbox: create temp sb file: %w", err)
	}
	sbPath := tmpFile.Name()
	defer os.Remove(sbPath) //nolint:errcheck

	if _, err := tmpFile.WriteString(sbProfile); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sandbox: write sb profile: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("sandbox: close sb profile: %w", err)
	}

	// Build sandbox-exec argv.
	// sandbox-exec -f <profile> env -i KEY=VAL... <executable>
	args, err := buildSandboxExecArgs(sbPath, m, extraEnv)
	if err != nil {
		return err
	}

	//nolint:gosec // G204: argv is constructed from validated manifest fields, not user input.
	cmd := exec.CommandContext(ctx, "sandbox-exec", args...)
	// Strip the calling process environment so KEYLATCH_* vars never leak
	// into sandbox-exec's startup environment or /proc/<pid>/environ.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	runErr := cmd.Run()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return fmt.Errorf("sandbox: sandbox-exec exited %d", exitErr.ExitCode())
		}
		return fmt.Errorf("sandbox: sandbox-exec: %w", runErr)
	}
	return nil
}

// generateSbProfile returns a TinyScheme sandbox profile that denies by
// default, allows the system paths, bind mounts and the executable, and then
// denies keylatch state and every Deny path. The denies come last because
// the last matching rule wins in a sandbox profile, so an allowed parent
// directory cannot re-open them.
func generateSbProfile(m *SandboxManifest) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get home dir: %w", err)
	}
	for _, d := range m.Deny {
		if !filepath.IsAbs(d) {
			return "", fmt.Errorf("%w: %q is not an absolute path", ErrDenyUnenforceable, d)
		}
	}

	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(deny default)\n")
	sb.WriteString("\n")

	sb.WriteString("; Allow read-only access to standard system paths\n")
	for _, p := range []string{"/usr", "/bin", "/lib", "/etc", "/System", "/Library"} {
		fmt.Fprintf(&sb, "(allow file-read* (subpath %q))\n", p)
	}
	sb.WriteString("\n")

	sb.WriteString("; Allow /dev access\n")
	sb.WriteString("(allow file-read* file-write* (subpath \"/dev\"))\n")
	sb.WriteString("\n")

	sb.WriteString("; Allow /tmp\n")
	sb.WriteString("(allow file-read* file-write* (subpath \"/tmp\"))\n")
	sb.WriteString("\n")

	if len(m.BindMounts) > 0 {
		sb.WriteString("; Allow manifest bind mounts\n")
		for _, bm := range m.BindMounts {
			src := filepath.Clean(bm.Src)
			if bm.RO {
				fmt.Fprintf(&sb, "(allow file-read* (subpath %q))\n", src)
			} else {
				fmt.Fprintf(&sb, "(allow file-read* file-write* (subpath %q))\n", src)
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("; Allow process execution\n")
	fmt.Fprintf(&sb, "(allow process-exec (literal %q))\n", filepath.Clean(m.Executable))
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString("\n")

	sb.WriteString("(allow signal (target self))\n")
	sb.WriteString("\n")

	sb.WriteString("; Deny keylatch state and manifest deny paths\n")
	seen := map[string]bool{}
	for _, p := range append(protectedPaths(home, llmcontext.DefaultLookup), m.Deny...) {
		for _, form := range pathForms(p) {
			if !seen[form] {
				seen[form] = true
				fmt.Fprintf(&sb, "(deny file-read* file-write* (subpath %q))\n", form)
			}
		}
	}

	return sb.String(), nil
}

// buildSandboxExecArgs constructs the sandbox-exec(1) argument vector.
//
// Structure:
//
//	sandbox-exec -f <profile.sb> env -i KEY=VALUE... <executable>
//
// Using env(1) with -i starts with an empty environment, then adds only the
// explicitly provided key-value pairs. This ensures provider credentials do
// not leak from the parent env.
func buildSandboxExecArgs(sbPath string, m *SandboxManifest, extraEnv []string) ([]string, error) {
	// sandbox-exec -f <path> env -i [KEY=VAL ...] <executable>
	args := []string{"-f", sbPath, "env", "-i"}

	// Inject manifest EnvInject vars.
	for k, v := range m.EnvInject {
		args = append(args, k+"="+v)
	}

	// Inject caller-provided extra env (e.g., injected credentials).
	for _, entry := range extraEnv {
		idx := indexOf(entry, '=')
		if idx < 0 {
			continue
		}
		args = append(args, entry)
	}

	// Executable.
	args = append(args, m.Executable)
	return args, nil
}
