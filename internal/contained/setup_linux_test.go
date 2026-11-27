package contained

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// fakeSys records every privileged call and answers file questions from a
// small in-memory tree, so the root assembly is tested without namespaces.
type fakeSys struct {
	calls   []string
	missing map[string]bool
	links   map[string]string
	dirs    map[string]bool
	files   map[string]bool
	failOn  string
	flags   uintptr
}

type fakeInfo struct {
	name string
	mode os.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

func (f *fakeSys) do(format string, a ...any) error {
	call := fmt.Sprintf(format, a...)
	f.calls = append(f.calls, call)
	if f.failOn != "" && strings.HasPrefix(call, f.failOn) {
		return errors.New("injected failure")
	}
	return nil
}

func (f *fakeSys) Mount(src, dst, fstype string, flags uintptr, data string) error {
	return f.do("mount %s %s %s %#x %s", orDash(src), dst, orDash(fstype), flags, data)
}
func (f *fakeSys) Unmount(dst string, flags int) error { return f.do("umount %s", dst) }
func (f *fakeSys) PivotRoot(newRoot, putOld string) error {
	return f.do("pivot %s %s", newRoot, putOld)
}
func (f *fakeSys) Chdir(dir string) error                 { return f.do("chdir %s", dir) }
func (f *fakeSys) MkdirAll(p string, _ os.FileMode) error { return f.do("mkdir %s", p) }
func (f *fakeSys) WriteFile(p string, _ []byte, _ os.FileMode) error {
	return f.do("write %s", p)
}
func (f *fakeSys) Symlink(target, link string) error { return f.do("symlink %s %s", target, link) }
func (f *fakeSys) Remove(p string) error             { return f.do("remove %s", p) }
func (f *fakeSys) SetHostname(n string) error        { return f.do("hostname %s", n) }
func (f *fakeSys) LoopbackUp() error                 { return f.do("lo up") }
func (f *fakeSys) MountFlags(string) (uintptr, error) {
	return f.flags, nil
}

func (f *fakeSys) Readlink(p string) (string, error) {
	if t, ok := f.links[p]; ok {
		return t, nil
	}
	return "", fs.ErrInvalid
}

func (f *fakeSys) Lstat(p string) (os.FileInfo, error) {
	switch {
	case f.missing[p]:
		return nil, fs.ErrNotExist
	case f.links[p] != "":
		return fakeInfo{p, os.ModeSymlink}, nil
	case f.files[p] || strings.Contains(filepath.Base(p), "."):
		return fakeInfo{p, 0o644}, nil
	case f.dirs[p] || true:
		return fakeInfo{p, os.ModeDir}, nil
	}
	return fakeInfo{p, 0o644}, nil
}

func (f *fakeSys) has(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (f *fakeSys) index(prefix string) int {
	for i, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return i
		}
	}
	return -1
}

func testSpec() Spec {
	s := Spec{
		Argv: []string{"true"}, Env: []string{"A=b"}, Project: "/work/project", EgressDir: "/run/user/1/e", RootDir: "/run/user/1/r",
		ReadOnly: []string{"/opt/toolchain"}, ReadWrite: []string{"/work/cache"},
	}
	_ = s.Validate()
	return s
}

func TestSetupRootBuildsAPrivateRootAndPivots(t *testing.T) {
	sys := &fakeSys{links: map[string]string{"/bin": "usr/bin", "/lib": "usr/lib"}, missing: map[string]bool{"/lib32": true, "/libx32": true, "/etc/pki": true}, flags: unix.MS_NOEXEC}
	spec := testSpec()
	require.NoError(t, setupRoot(sys, spec, "/usr/bin/keylatch"))

	assert.Equal(t, 0, sys.index("mount - / - "), "the mount tree is made private first")
	assert.Less(t, sys.index("mount tmpfs /tmp"), sys.index("mount /work/project"), "tmpfs scratch directories come before binds that may sit below them")
	assert.True(t, sys.has("symlink usr/bin /run/user/1/r/bin"), "merged-usr links are recreated")
	assert.True(t, sys.has("mount /usr /run/user/1/r/usr"))
	assert.False(t, sys.has("mount /lib32"), "missing optional sources are skipped")
	assert.True(t, sys.has("mount /usr/bin/keylatch /run/user/1/r"+initBinaryPath))
	assert.True(t, sys.has("mount /work/project /run/user/1/r/work/project"))
	assert.True(t, sys.has("mount /run/user/1/e /run/user/1/r"+EgressMount))
	assert.True(t, sys.has("mount /opt/toolchain"), "read-only extras are mounted")
	assert.True(t, sys.has("mount proc /run/user/1/r/proc proc"))
	assert.Less(t, sys.index("mount proc"), sys.index("pivot"), "procfs is mounted while the host's /proc is visible")
	assert.True(t, sys.has("pivot /run/user/1/r /run/user/1/r/.old"))
	assert.True(t, sys.has("umount /.old"))
	assert.True(t, sys.has("remove /.old"))

	var remount string
	for _, c := range sys.calls {
		if strings.HasPrefix(c, "mount - /run/user/1/r/usr -") {
			remount = c
		}
	}
	assert.Contains(t, remount, fmt.Sprintf("%#x", uintptr(unix.MS_BIND|unix.MS_REMOUNT|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_RDONLY|unix.MS_NOEXEC)),
		"the read-only remount keeps the flags the kernel locks")
}

func TestSetupRootWritesHoneyFilesIntoTheHome(t *testing.T) {
	sys := &fakeSys{missing: map[string]bool{}}
	spec := testSpec()
	spec.Honey = []HoneyFile{{Path: ".aws/credentials", Content: "[default]\n"}, {Path: ".npmrc", Content: "//registry\n"}}
	require.NoError(t, setupRoot(sys, spec, "/helper"))
	assert.True(t, sys.has("write /run/user/1/r"+DefaultHome+"/.aws/credentials"))
	assert.True(t, sys.has("write /run/user/1/r"+DefaultHome+"/.npmrc"))
	assert.Less(t, sys.index("mount tmpfs "+"/run/user/1/r"+DefaultHome), sys.index("write /run/user/1/r"+DefaultHome+"/.npmrc"), "the home is mounted before the files land in it")

	sys = &fakeSys{failOn: "write /run/user/1/r" + DefaultHome, missing: map[string]bool{}}
	assert.Error(t, setupRoot(sys, spec, "/helper"))
	sys = &fakeSys{failOn: "mkdir /run/user/1/r" + DefaultHome + "/.aws", missing: map[string]bool{}}
	assert.Error(t, setupRoot(sys, spec, "/helper"))
}

func TestSetupRootReportsTheFailingStep(t *testing.T) {
	for _, step := range []string{"mount - /", "mount tmpfs /run/user/1/r ", "mount /work/project", "mount proc", "pivot", "umount", "remove", "mkdir /run/user/1/r/.old", "chdir"} {
		sys := &fakeSys{failOn: step, missing: map[string]bool{}}
		assert.Error(t, setupRoot(sys, testSpec(), "/helper"), step)
	}
	sys := &fakeSys{missing: map[string]bool{"/work/project": true}}
	assert.ErrorContains(t, setupRoot(sys, testSpec(), "/helper"), "mount source /work/project")
}

func TestSetupRootToleratesMissingOptionalDeviceMounts(t *testing.T) {
	sys := &fakeSys{failOn: "mount devpts", missing: map[string]bool{"/dev/tty": true}}
	require.NoError(t, setupRoot(sys, testSpec(), "/helper"))
	assert.False(t, sys.has("symlink pts/ptmx"))
	assert.True(t, sys.has("symlink /proc/self/fd /run/user/1/r/dev/fd"))
}

func TestPivotMasksProcFiles(t *testing.T) {
	sys := &fakeSys{files: map[string]bool{"/proc/kcore": true, "/proc/keys": true}}
	require.NoError(t, pivot(sys, "/r"))
	assert.True(t, sys.has("mount /proc/sys /proc/sys"))
	assert.True(t, sys.has("mount /dev/null /proc/kcore"))
	assert.True(t, sys.has("mount tmpfs /proc/scsi tmpfs"), "a masked directory becomes an empty read-only tmpfs")
}

func TestSandboxPathsListWhatTheChildMayTouch(t *testing.T) {
	ro, rw := sandboxPaths(testSpec())
	assert.Contains(t, ro, "/usr")
	assert.Contains(t, ro, "/opt/toolchain")
	assert.Contains(t, ro, EgressMount)
	assert.Contains(t, rw, "/work/project")
	assert.Contains(t, rw, "/work/cache")
	assert.Contains(t, rw, "/tmp")
	assert.NotContains(t, rw, "/etc")
	assert.NotContains(t, rw, "/usr")
}

func TestMountFlagsOfTheHostFilesystem(t *testing.T) {
	flags, err := hostSys{}.MountFlags("/")
	require.NoError(t, err)
	assert.Zero(t, flags&^uintptr(inheritedMountFlags))
	_, err = hostSys{}.MountFlags("/nonexistent/path")
	assert.Error(t, err)
}

func TestHostSysFileHelpers(t *testing.T) {
	dir := t.TempDir()
	h := hostSys{}
	require.NoError(t, h.MkdirAll(filepath.Join(dir, "a", "b"), 0o755))
	require.NoError(t, h.WriteFile(filepath.Join(dir, "a", "f"), []byte("x"), 0o600))
	require.NoError(t, h.Symlink("f", filepath.Join(dir, "a", "l")))
	target, err := h.Readlink(filepath.Join(dir, "a", "l"))
	require.NoError(t, err)
	assert.Equal(t, "f", target)
	info, err := h.Lstat(filepath.Join(dir, "a", "l"))
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink)
	require.NoError(t, h.Remove(filepath.Join(dir, "a", "l")))
	assert.Error(t, h.Mount("", dir, "tmpfs", 0, ""), "an unprivileged mount fails")
	assert.Error(t, h.Unmount(dir, 0))
	assert.Error(t, h.PivotRoot(dir, dir))
	assert.Error(t, h.Chdir(filepath.Join(dir, "missing")))
	assert.Equal(t, "-", orDash(""))
	assert.Equal(t, "x", orDash("x"))
}

type fakeRestrictor struct {
	calls   []string
	abi     int
	failOn  string
	program int
}

func (f *fakeRestrictor) step(name string) error {
	f.calls = append(f.calls, name)
	if f.failOn == name {
		return errors.New("injected")
	}
	return nil
}
func (f *fakeRestrictor) NoNewPrivs() error       { return f.step("nnp") }
func (f *fakeRestrictor) DropCapabilities() error { return f.step("caps") }
func (f *fakeRestrictor) LandlockABI() int        { return f.abi }
func (f *fakeRestrictor) Landlock(p landlockPlan) error {
	f.program = len(p.paths)
	return f.step("landlock")
}
func (f *fakeRestrictor) Seccomp(p []unix.SockFilter) error {
	if len(p) == 0 {
		return errors.New("empty program")
	}
	return f.step("seccomp")
}

func TestRestrictAppliesEveryLayerInOrder(t *testing.T) {
	r := &fakeRestrictor{abi: 4}
	require.NoError(t, restrict(r, testSpec()))
	assert.Equal(t, []string{"nnp", "caps", "landlock", "seccomp"}, r.calls)
}

func TestRestrictFailsClosed(t *testing.T) {
	for _, step := range []string{"nnp", "caps", "landlock", "seccomp"} {
		r := &fakeRestrictor{abi: 4, failOn: step}
		assert.Error(t, restrict(r, testSpec()), step)
	}
	r := &fakeRestrictor{abi: 0}
	assert.ErrorContains(t, restrict(r, testSpec()), "no Landlock")
	assert.Equal(t, []string{"nnp", "caps"}, r.calls, "nothing runs when Landlock is missing")
}

func TestExecTargetOrdersRestrictionsBeforeTheExec(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "tool")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755))
	spec := testSpec()
	spec.Argv, spec.Env, spec.Dir = []string{"tool", "arg"}, []string{"PATH=" + dir, "SECRET=v"}, dir

	var restricted bool
	var gotPath string
	var gotEnv []string
	r := &fakeRestrictor{abi: 1}
	var stderr bytes.Buffer
	execve := func(path string, argv, env []string) error {
		restricted = len(r.calls) == 4
		gotPath, gotEnv = path, env
		return syscall.ENOENT
	}
	code := execTarget(r, spec, execve, &stderr)
	assert.True(t, restricted, "every restriction is in place at the exec")
	assert.Equal(t, bin, gotPath)
	assert.Equal(t, []string{"PATH=" + dir, "SECRET=v"}, gotEnv)
	assert.Equal(t, exitNotFound, code)

	code = execTarget(r, spec, func(string, []string, []string) error { return syscall.EACCES }, &stderr)
	assert.Equal(t, exitExecFailed, code)
}

func TestExecTargetFailures(t *testing.T) {
	spec := testSpec()
	spec.Dir = "/nonexistent-dir-for-test"
	var stderr bytes.Buffer
	assert.Equal(t, exitSetupFailed, execTarget(&fakeRestrictor{abi: 1}, spec, nil, &stderr))
	assert.Contains(t, stderr.String(), "working directory")

	spec.Dir = t.TempDir()
	spec.Argv = []string{"definitely-not-a-command"}
	spec.Env = []string{"PATH=" + spec.Dir}
	stderr.Reset()
	r := &fakeRestrictor{abi: 1}
	assert.Equal(t, exitNotFound, execTarget(r, spec, nil, &stderr))
	assert.Contains(t, stderr.String(), "command not found")
	assert.Len(t, r.calls, 4, "the restrictions are applied even when the command is missing")

	stderr.Reset()
	assert.Equal(t, exitSetupFailed, execTarget(&fakeRestrictor{abi: 1, failOn: "seccomp"}, spec, nil, &stderr))
}

func TestLookPath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "tool"), nil, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "data"), nil, 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o755))
	p, ok := lookPath([]string{"PATH=" + dir}, "tool")
	assert.True(t, ok)
	assert.Equal(t, filepath.Join(dir, "tool"), p)
	_, ok = lookPath([]string{"PATH=" + dir}, "data")
	assert.False(t, ok, "a file without the execute bit is not a command")
	_, ok = lookPath([]string{"PATH=" + dir}, "sub")
	assert.False(t, ok)
	p, ok = lookPath(nil, "/abs/tool")
	assert.True(t, ok)
	assert.Equal(t, "/abs/tool", p)
	_, ok = lookPath([]string{"PATH=:"}, "tool")
	assert.False(t, ok, "an empty PATH entry means the working directory, which has no tool")
}

func TestStatusCode(t *testing.T) {
	assert.Equal(t, 0, statusCode(syscall.WaitStatus(0)))
	assert.Equal(t, 7, statusCode(syscall.WaitStatus(7<<8)))
	assert.Equal(t, 128+9, statusCode(syscall.WaitStatus(9)))
}

func TestReadConfigValidates(t *testing.T) {
	read := func(payload string) (initConfig, error) {
		r, w, err := os.Pipe()
		require.NoError(t, err)
		go func() { _, _ = w.WriteString(payload); _ = w.Close() }()
		cfg, _, err := readConfig(r)
		return cfg, err
	}
	cfg, err := read(`{"spec":{"argv":["x"],"env":["A=b"],"project":"/p","egress_dir":"/e","root_dir":"/r"},"helper":"/h"}`)
	require.NoError(t, err)
	assert.Equal(t, "/h", cfg.Helper)
	assert.Equal(t, DefaultProxyPort, cfg.Spec.ProxyPort)
	_, err = read(`not json`)
	assert.ErrorContains(t, err, "parse configuration")
	_, err = read(`{"spec":{"argv":[]}}`)
	assert.ErrorContains(t, err, "command is required")
}
