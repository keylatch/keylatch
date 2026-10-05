//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/audit"
)

// RunSandboxed executes m.Executable inside a bwrap sandbox.
//
// Security properties:
// - Executable hash is verified before exec.
// - No bind mount may expose keylatch state; every Deny path is masked.
// - Only explicit EnvInject vars are passed; inherit is false.
// - No shell string construction — argv is a slice.
// - KEYLATCH_* vars are never exposed in bwrap's environment (cmd.Env is set explicitly).
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

	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("sandbox: get home dir: %w", err)
	}
	if err := validateBindMountsWithHome(m, home); err != nil {
		return err
	}

	args, err := buildBwrapArgs(m, extraEnv)
	if err != nil {
		return err
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

	//nolint:gosec // G204: argv is constructed from validated manifest fields, not user input.
	cmd := exec.CommandContext(ctx, "bwrap", args...)
	// Strip the calling process environment so KEYLATCH_* vars never leak
	// into bwrap's startup environment or /proc/<pid>/environ.
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
//	  --ro-bind /lib64 /lib64 (if exists)
//	  --ro-bind /bin /bin
//	  --ro-bind /etc /etc
//	  --dev /dev
//	  --proc /proc
//	  --tmpfs /tmp
//	  [manifest bind mounts]
//	  [--tmpfs <dir> | --ro-bind /dev/null <file> for each Deny path]
//	  --setenv KEY val (for each EnvInject)
//	  --unsetenv HOME (prevent host home leaking)
//	  -- <executable> [args]
func buildBwrapArgs(m *SandboxManifest, extraEnv []string) ([]string, error) {
	var args []string
	var mounts []sandboxMount

	systemDirs := []string{"/usr", "/lib", "/bin", "/etc"}
	if pathExists("/lib64") {
		systemDirs = append(systemDirs, "/lib64")
	}
	for _, path := range systemDirs {
		args = append(args, "--ro-bind", path, path)
		mounts = append(mounts, sandboxMount{dest: path, src: path})
	}

	args = append(args, "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp")
	mounts = append(mounts, sandboxMount{dest: "/dev"}, sandboxMount{dest: "/proc"}, sandboxMount{dest: "/tmp"})

	for _, bm := range m.BindMounts {
		flag := "--bind"
		if bm.RO {
			flag = "--ro-bind"
		}
		args = append(args, flag, bm.Src, bm.Dest)
		mounts = append(mounts, sandboxMount{dest: filepath.Clean(bm.Dest), src: filepath.Clean(bm.Src)})
	}

	// Masks go after every bind: bwrap applies mounts in argv order, so an
	// earlier mask would be covered by a later bind of a parent directory.
	masks, err := bwrapDenyArgs(m.Deny, mounts)
	if err != nil {
		return nil, err
	}
	args = append(args, masks...)

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

// sandboxMount is one mount in the sandbox; src is empty for mounts with no
// host backing (devtmpfs, procfs, tmpfs).
type sandboxMount struct {
	dest string
	src  string
}

// bwrapDenyArgs masks each deny path: a directory is covered with an empty
// tmpfs, anything else with /dev/null. A path no host-backed mount exposes,
// or that does not exist on the host, has nothing to mask. A symlink cannot
// be masked reliably, so it refuses to start.
func bwrapDenyArgs(deny []string, mounts []sandboxMount) ([]string, error) {
	var args []string
	for _, raw := range deny {
		if !filepath.IsAbs(raw) {
			return nil, fmt.Errorf("%w: %q is not an absolute path", ErrDenyUnenforceable, raw)
		}
		p := filepath.Clean(raw)
		host, ok := hostPathFor(p, mounts)
		if !ok {
			continue
		}
		info, err := os.Lstat(host)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrDenyUnenforceable, raw, err)
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return nil, fmt.Errorf("%w: %q is a symlink", ErrDenyUnenforceable, raw)
		case info.IsDir():
			args = append(args, "--tmpfs", p)
		default:
			args = append(args, "--ro-bind", "/dev/null", p)
		}
	}
	return args, nil
}

// hostPathFor maps a sandbox path to the host path behind it, using the last
// mount covering it since later mounts shadow earlier ones.
func hostPathFor(p string, mounts []sandboxMount) (string, bool) {
	for i := len(mounts) - 1; i >= 0; i-- {
		mt := mounts[i]
		if !isUnder(p, mt.dest) {
			continue
		}
		if mt.src == "" {
			return "", false
		}
		rel, err := filepath.Rel(mt.dest, p)
		if err != nil {
			return "", false
		}
		return filepath.Join(mt.src, rel), true
	}
	return "", false
}

// pathExists returns true if path exists.
func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
