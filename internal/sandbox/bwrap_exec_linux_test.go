//go:build linux

package sandbox_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type gdEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (e *gdEmitter) Emit(_ context.Context, ev audit.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
	return nil
}

// gdBwrapDir writes a fake bwrap that records argv and exported env, then
// exits with code, and returns the directory holding it.
func gdBwrapDir(t *testing.T, code int) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"if [ -n \"$BWRAP_ARGV_DUMP\" ]; then\n" +
		"  for a in \"$@\"; do printf '%s\\n' \"$a\" >> \"$BWRAP_ARGV_DUMP\"; done\n" +
		"  export -p > \"$BWRAP_ARGV_DUMP.env\"\n" +
		"fi\n" +
		"exit " + string(rune('0'+code)) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bwrap"), []byte(script), 0o755))
	return dir
}

func gdManifest(t *testing.T) *sandbox.SandboxManifest {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "tool")
	content := []byte("#!/bin/sh\nexit 0\n")
	require.NoError(t, os.WriteFile(p, content, 0o755))
	sum := sha256.Sum256(content)
	return &sandbox.SandboxManifest{
		ProfileID:  "t",
		Executable: p,
		ExecHash:   hex.EncodeToString(sum[:]),
		BindMounts: []sandbox.BindMount{{Src: dir, Dest: "/ro", RO: true}},
		Deny:       []string{"/srv/secret"},
	}
}

func TestRunSandboxed_StripsParentEnvAndEmitsDenyEvent(t *testing.T) {
	gdTempHome(t)
	bin := gdBwrapDir(t, 0)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	dump := filepath.Join(t.TempDir(), "argv")
	t.Setenv("BWRAP_ARGV_DUMP", dump)
	t.Setenv("KEYLATCH_MASTER_PASSPHRASE", "parent-only-value")
	t.Setenv("GD_PARENT_ONLY", "leak")

	m := gdManifest(t)
	em := &gdEmitter{}
	err := sandbox.RunSandboxed(context.Background(), m, true, []string{"NOEQUALS", "TOKEN=a=b"}, em)
	require.NoError(t, err)

	argv, err := os.ReadFile(dump)
	require.NoError(t, err)
	joined := strings.ReplaceAll(strings.TrimSpace(string(argv)), "\n", " ")
	assert.Contains(t, joined, "--ro-bind "+filepath.Dir(m.Executable)+" /ro")
	assert.Contains(t, joined, "--setenv TOKEN a=b", "value is split on the first '=' only")
	assert.NotContains(t, joined, "NOEQUALS", "entries without '=' must be dropped")
	assert.Contains(t, joined, "--unsetenv USER")
	assert.Contains(t, joined, "--unsetenv XDG_RUNTIME_DIR")
	assert.True(t, strings.HasSuffix(joined, "-- "+m.Executable))

	envDump, err := os.ReadFile(dump + ".env")
	require.NoError(t, err)
	assert.NotContains(t, string(envDump), "KEYLATCH_MASTER_PASSPHRASE")
	assert.NotContains(t, string(envDump), "parent-only-value")
	assert.NotContains(t, string(envDump), "GD_PARENT_ONLY")
	assert.Contains(t, string(envDump), "PATH=")

	em.mu.Lock()
	defer em.mu.Unlock()
	require.Len(t, em.events, 1)
	assert.Equal(t, audit.ActionSandboxDenyApplied, em.events[0].Action)
	assert.Equal(t, audit.OutcomeOK, em.events[0].Outcome)
	assert.Equal(t, []string{"/srv/secret"}, em.events[0].Extra["denied_paths"])
}

func TestRunSandboxed_NonZeroExit(t *testing.T) {
	gdTempHome(t)
	bin := gdBwrapDir(t, 3)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("BWRAP_ARGV_DUMP", "")

	err := sandbox.RunSandboxed(context.Background(), gdManifest(t), true, nil, nil)
	require.Error(t, err)
	assert.Equal(t, "sandbox: bwrap exited 3", err.Error())
}

func TestRunSandboxed_BwrapNotOnPath(t *testing.T) {
	gdTempHome(t)
	t.Setenv("PATH", t.TempDir())

	err := sandbox.RunSandboxed(context.Background(), gdManifest(t), true, nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, exec.ErrNotFound), "got %v", err)
}

func TestRunSandboxed_ValidationBeforeAnyEvent(t *testing.T) {
	home := gdTempHome(t)
	m := gdManifest(t)
	m.BindMounts = append(m.BindMounts, sandbox.BindMount{Src: filepath.Join(home, ".keylatch"), Dest: "/k"})
	em := &gdEmitter{}

	err := sandbox.RunSandboxed(context.Background(), m, true, nil, em)
	require.ErrorIs(t, err, sandbox.ErrForbiddenMount)
	assert.Empty(t, em.events, "no deny-applied event when validation refuses the manifest")

	m2 := gdManifest(t)
	require.NoError(t, os.WriteFile(m2.Executable, []byte("#!/bin/sh\necho swapped\n"), 0o755))
	err = sandbox.RunSandboxed(context.Background(), m2, true, nil, em)
	require.ErrorIs(t, err, sandbox.ErrHashMismatch)
	assert.Empty(t, em.events)
}

func TestRunSandboxed_HomeUnset(t *testing.T) {
	t.Setenv("HOME", "")
	err := sandbox.RunSandboxed(context.Background(), gdManifest(t), true, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get home dir")
}

func TestDetectBwrap(t *testing.T) {
	bin := gdBwrapDir(t, 0)
	t.Setenv("PATH", bin)
	p, ok := sandbox.DetectBwrap()
	require.True(t, ok)
	assert.Equal(t, filepath.Join(bin, "bwrap"), p)

	t.Setenv("PATH", t.TempDir())
	p, ok = sandbox.DetectBwrap()
	_, errUsr := os.Stat("/usr/bin/bwrap")
	_, errLocal := os.Stat("/usr/local/bin/bwrap")
	if errUsr != nil && errLocal != nil {
		assert.False(t, ok)
		assert.Empty(t, p)
	} else {
		assert.True(t, ok)
		assert.True(t, strings.HasSuffix(p, "/bin/bwrap"))
	}
	assert.Contains(t, sandbox.ErrBwrapMissing.Error(), "bubblewrap")
}
