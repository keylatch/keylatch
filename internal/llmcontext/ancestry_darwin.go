package llmcontext

import (
	"bytes"

	"golang.org/x/sys/unix"
)

func kinfo(pid int) (*unix.KinfoProc, error) {
	return unix.SysctlKinfoProc("kern.proc.pid", pid)
}

func readProcessInfo(pid int) (Process, error) {
	kp, err := kinfo(pid)
	if err != nil {
		return Process{}, err
	}
	comm := kp.Proc.P_comm[:]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	tv := kp.Proc.P_starttime
	start := uint64(tv.Sec)*1_000_000 + uint64(tv.Usec) //nolint:gosec // process start times are positive
	return Process{PID: pid, Start: start, Names: uniqueNames(string(comm))}, nil
}

func parentPID(pid int) (int, error) {
	kp, err := kinfo(pid)
	if err != nil {
		return 0, err
	}
	return int(kp.Eproc.Ppid), nil
}
