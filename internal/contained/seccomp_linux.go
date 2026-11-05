//go:build linux && (amd64 || arm64)

package contained

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccomp_data field offsets.
const (
	offNr   = 0
	offArch = 4
	offArg0 = 16
)

// namespaceCloneFlags are the clone flags that would create a namespace.
const namespaceCloneFlags = unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWTIME

// deniedSyscalls fail with EPERM: tracing and memory access across processes,
// kernel keyrings and BPF, anything that changes mounts or roots, namespace
// creation, and module and reboot interfaces.
var deniedSyscalls = []uint32{
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_PIDFD_GETFD, unix.SYS_KCMP,
	unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	unix.SYS_MOUNT_SETATTR, unix.SYS_MOVE_MOUNT, unix.SYS_OPEN_TREE, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK,
	unix.SYS_UNSHARE, unix.SYS_SETNS,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_REBOOT, unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_ACCT, unix.SYS_OPEN_BY_HANDLE_AT,
}

var ioUringSyscalls = []uint32{unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER}

// filterSpec is the policy a seccomp filter encodes.
type filterSpec struct {
	arch uint32
	// eperm and enosys list syscalls refused with that error. clone3 gets
	// ENOSYS because its flags live in memory the filter cannot read; libc
	// then falls back to clone, whose flags it can.
	eperm, enosys []uint32
	cloneNr       uint32
	cloneMask     uint32
	// rejectHighNumbers kills a call whose number has bit 30 set, the x32 ABI
	// that would bypass number-based rules on amd64.
	rejectHighNumbers bool
}

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k, Jt: jt, Jf: jf}
}

func ret(action uint32) unix.SockFilter { return stmt(unix.BPF_RET|unix.BPF_K, action) }

func errnoAction(e unix.Errno) uint32 { return unix.SECCOMP_RET_ERRNO | uint32(e) } //nolint:gosec // G115: errno values are small

// build renders the filter as classic BPF.
func (f filterSpec) build() []unix.SockFilter {
	loadNr := stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offNr)
	prog := []unix.SockFilter{
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offArch),
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, f.arch, 1, 0),
		ret(unix.SECCOMP_RET_KILL_PROCESS),
		loadNr,
	}
	if f.rejectHighNumbers {
		prog = append(prog,
			jump(unix.BPF_JMP|unix.BPF_JGE|unix.BPF_K, 0x40000000, 0, 1),
			ret(unix.SECCOMP_RET_KILL_PROCESS),
		)
	}
	deny := func(nrs []uint32, action uint32) {
		for _, nr := range nrs {
			prog = append(prog, jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, nr, 0, 1), ret(action))
		}
	}
	deny(f.eperm, errnoAction(unix.EPERM))
	deny(f.enosys, errnoAction(unix.ENOSYS))
	prog = append(prog,
		jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, f.cloneNr, 0, 4),
		stmt(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offArg0),
		jump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, f.cloneMask, 0, 1),
		ret(errnoAction(unix.EPERM)),
		loadNr,
		ret(unix.SECCOMP_RET_ALLOW),
	)
	return prog
}

// defaultFilter is the filter every contained child runs under.
func defaultFilter(allowIOUring bool) []unix.SockFilter {
	f := filterSpec{
		arch:      nativeArch,
		eperm:     append([]uint32(nil), deniedSyscalls...),
		enosys:    []uint32{unix.SYS_CLONE3},
		cloneNr:   unix.SYS_CLONE,
		cloneMask: namespaceCloneFlags,

		rejectHighNumbers: nativeArch == unix.AUDIT_ARCH_X86_64,
	}
	if !allowIOUring {
		f.eperm = append(f.eperm, ioUringSyscalls...)
	}
	return f.build()
}

var errNoProgram = errors.New("contained: empty seccomp program")

// installFilter loads prog for the calling thread and every thread it creates
// afterwards. no_new_privs must already be set.
func installFilter(prog []unix.SockFilter) error {
	if len(prog) == 0 {
		return errNoProgram
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}                                                                    //nolint:gosec // G115: the program is far shorter than 65535 instructions
	if _, _, e := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog))); e != 0 { //nolint:gosec // G103: the kernel copies the program during the call
		return fmt.Errorf("contained: load seccomp filter: %w", e)
	}
	return nil
}
