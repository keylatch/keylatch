//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/keylatch/keylatch/internal/audit"
)

// RunSandboxed executes m.Executable inside a bwrap sandbox.
//
// Security properties:
//   - Executable hash is verified before exec.
//   - ~/.keylatch is denied in bind-mount list.
//   - Only explicit EnvInject vars are passed; inherit is false.
//   - No shell string construction — argv is a slice.
//   - KEYLATCH_* vars are never exposed in bwrap's environment (cmd.Env is set explicitly).
//
// If featureEnabled is false, ErrFeatureFlagRequired is returned.
func RunSandboxed(ctx context.Context, m *SandboxManifest, featureEnabled bool, extraEnv []string, emitter audit.Emitter) error {
	if !featureEnabled {
		return ErrFeatureFlagRequired
	}

	// Verify executable hash.
	if err := VerifyExecHash(m); err != nil {
		return err
	}

	// Validate bind mounts (deny ~/.keylatch).
	// S5: pre-compute homeDir once here and pass it to avoid a duplicate
	// os.UserHomeDir() call inside validateBindMountsWithHome.
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("sandbox: get home dir: %w", err)
	}
	if err := validateBindMountsWithHome(m, home); err != nil {
		return err
	}

	// Emit deny-applied audit event now that the deny-list validation passed.
	if emitter != nil {
		_ = emitter.Emit(ctx, audit.Event{
			Action:  audit.ActionSandboxDenyApplied,
			Outcome: audit.OutcomeOK,
			Extra: map[string]any{
				"denied_paths": m.Deny,
			},
		})
	}

	// Build bwrap argv.
	args, err := buildBwrapArgs(m, extraEnv)
	if err != nil {
		return err
	}

	//nolint:gosec // G204: argv is constructed from validated manifest fields, not user input.
	cmd := exec.CommandContext(ctx, "bwrap", args...)
	// Strip the calling process environment so KEYLATCH_* vars never leak
	// into bwrap's startup environment or /proc/<pid>/environ (C1).
	// Preserve BWRAP_ARGV_DUMP when set (test-only env var for argv introspection).
	env := []string{"PATH=" + os.Getenv("PATH")}
	if dump := os.Getenv("BWRAP_ARGV_DUMP"); dump != "" {
		env = append(env, "BWRAP_ARGV_DUMP="+dump)
	}
	cmd.Env = env
	runErr := cmd.Run()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			// Non-zero exit: wrap exit code.
			return fmt.Errorf("sandbox: bwrap exited %d", exitErr.ExitCode())
		}
		return fmt.Errorf("sandbox: bwrap: %w", runErr)
	}
	return nil
}

// buildBwrapArgs constructs the bwrap(1) argument vector for the manifest.
//
// Structure:
//
//	bwrap
//	  --ro-bind /usr /usr
//	  --ro-bind /lib /lib
//	  --ro-bind /lib64 /lib64   (if exists)
//	  --ro-bind /bin /bin
//	  --ro-bind /etc /etc
//	  --dev /dev
//	  --proc /proc
//	  --tmpfs /tmp
//	  [manifest bind mounts]
//	  --setenv KEY val   (for each EnvInject)
//	  --unsetenv HOME    (prevent host home leaking)
//	  -- <executable> [args]
func buildBwrapArgs(m *SandboxManifest, extraEnv []string) ([]string, error) {
	var args []string

	// Standard read-only system bindings.
	for _, path := range []string{"/usr", "/lib", "/bin", "/etc"} {
		args = append(args, "--ro-bind", path, path)
	}
	// lib64 may not exist on all systems.
	if pathExists("/lib64") {
		args = append(args, "--ro-bind", "/lib64", "/lib64")
	}

	// Pseudo-filesystems.
	args = append(args, "--dev", "/dev")
	args = append(args, "--proc", "/proc")
	args = append(args, "--tmpfs", "/tmp")

	// Manifest bind mounts.
	for _, bm := range m.BindMounts {
		flag := "--bind"
		if bm.RO {
			flag = "--ro-bind"
		}
		args = append(args, flag, bm.Src, bm.Dest)
	}

	// Clear inherited environment: unset HOME, USER, and other sensitive vars.
	args = append(args, "--unsetenv", "HOME")
	args = append(args, "--unsetenv", "USER")
	args = append(args, "--unsetenv", "XDG_RUNTIME_DIR")

	// Inject manifest EnvInject vars.
	for k, v := range m.EnvInject {
		args = append(args, "--setenv", k, v)
	}

	// Inject caller-provided extra env (e.g., injected credentials).
	for _, entry := range extraEnv {
		// Parse KEY=VALUE.
		idx := indexOf(entry, '=')
		if idx < 0 {
			continue
		}
		k := entry[:idx]
		v := entry[idx+1:]
		args = append(args, "--setenv", k, v)
	}

	// Executable.
	args = append(args, "--", m.Executable)
	return args, nil
}

// pathExists returns true if path exists.
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
