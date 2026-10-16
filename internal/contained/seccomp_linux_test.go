//go:build linux && (amd64 || arm64)

package contained

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// evalBPF interprets the subset of classic BPF the filter uses against a
// seccomp_data record and returns the filter's verdict.
func evalBPF(t *testing.T, prog []unix.SockFilter, nr, arch uint32, arg0 uint64) uint32 {
	t.Helper()
	var data [64]byte
	binary.LittleEndian.PutUint32(data[offNr:], nr)
	binary.LittleEndian.PutUint32(data[offArch:], arch)
	binary.LittleEndian.PutUint64(data[offArg0:], arg0)
	var a uint32
	jump := func(in unix.SockFilter, cond bool) int {
		if cond {
			return int(in.Jt)
		}
		return int(in.Jf)
	}
	for pc := 0; pc < len(prog); {
		in := prog[pc]
		pc++
		switch in.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			a = binary.LittleEndian.Uint32(data[in.K:])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			pc += jump(in, a == in.K)
		case unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K:
			pc += jump(in, a >= in.K)
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			pc += jump(in, a&in.K != 0)
		case unix.BPF_RET | unix.BPF_K:
			return in.K
		default:
			t.Fatalf("unexpected instruction %#x", in.Code)
		}
	}
	t.Fatal("the program fell off its end")
	return 0
}

func TestFilterDeniesDangerousSyscalls(t *testing.T) {
	prog := defaultFilter(false)
	eperm := unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	for _, nr := range append(append([]uint32{}, deniedSyscalls...), ioUringSyscalls...) {
		assert.Equal(t, eperm, evalBPF(t, prog, nr, nativeArch, 0), "syscall %d", nr)
	}
	assert.Equal(t, unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS), evalBPF(t, prog, unix.SYS_CLONE3, nativeArch, 0))
}

func TestFilterAllowsOrdinaryProgramBehaviour(t *testing.T) {
	prog := defaultFilter(false)
	for _, nr := range []uint32{unix.SYS_READ, unix.SYS_WRITE, unix.SYS_OPENAT, unix.SYS_EXECVE, unix.SYS_MMAP, unix.SYS_SOCKET,
		unix.SYS_CONNECT, unix.SYS_FUTEX, unix.SYS_EXIT_GROUP, unix.SYS_PRCTL, unix.SYS_SETSID, unix.SYS_KILL} {
		assert.Equal(t, uint32(unix.SECCOMP_RET_ALLOW), evalBPF(t, prog, nr, nativeArch, 0), "syscall %d", nr)
	}
	// A plain fork, a thread and a vfork are ordinary uses of clone.
	for _, flags := range []uint64{uint64(unix.SIGCHLD), unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD, unix.CLONE_VFORK | unix.CLONE_VM} {
		assert.Equal(t, uint32(unix.SECCOMP_RET_ALLOW), evalBPF(t, prog, unix.SYS_CLONE, nativeArch, flags), "clone %#x", flags)
	}
}

func TestFilterRefusesNamespaceClones(t *testing.T) {
	prog := defaultFilter(false)
	for _, flag := range []uint64{unix.CLONE_NEWUSER, unix.CLONE_NEWNS, unix.CLONE_NEWNET, unix.CLONE_NEWPID, unix.CLONE_NEWIPC,
		unix.CLONE_NEWUTS, unix.CLONE_NEWCGROUP, unix.CLONE_NEWTIME} {
		assert.Equal(t, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM), evalBPF(t, prog, unix.SYS_CLONE, nativeArch, uint64(unix.SIGCHLD)|flag), "flag %#x", flag)
	}
}

func TestFilterKillsAForeignArchitecture(t *testing.T) {
	prog := defaultFilter(false)
	assert.Equal(t, uint32(unix.SECCOMP_RET_KILL_PROCESS), evalBPF(t, prog, unix.SYS_READ, unix.AUDIT_ARCH_I386, 0))
	if nativeArch == unix.AUDIT_ARCH_X86_64 {
		assert.Equal(t, uint32(unix.SECCOMP_RET_KILL_PROCESS), evalBPF(t, prog, 0x40000000|unix.SYS_READ, nativeArch, 0), "the x32 ABI bypass")
	}
}

func TestIOUringCanBeAllowed(t *testing.T) {
	prog := defaultFilter(true)
	for _, nr := range ioUringSyscalls {
		assert.Equal(t, uint32(unix.SECCOMP_RET_ALLOW), evalBPF(t, prog, nr, nativeArch, 0))
	}
	assert.Equal(t, unix.SECCOMP_RET_ERRNO|uint32(unix.EPERM), evalBPF(t, prog, unix.SYS_PTRACE, nativeArch, 0))
}

func TestInstallFilterRejectsAnEmptyProgram(t *testing.T) {
	assert.ErrorIs(t, installFilter(nil), errNoProgram)
}

func TestBuildFilterShape(t *testing.T) {
	prog := filterSpec{arch: 1, eperm: []uint32{5}, cloneNr: 56, cloneMask: 0x10}.build()
	require.NotEmpty(t, prog)
	assert.Equal(t, uint32(unix.SECCOMP_RET_ALLOW), prog[len(prog)-1].K)
}
