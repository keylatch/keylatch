package llmcontext

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

type snapshotEntry struct {
	parent int
	exe    string
}

func snapshotProcesses() (map[int]snapshotEntry, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap) //nolint:errcheck // read-only snapshot handle
	entries := map[int]snapshotEntry{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(snap, &pe); err == nil; err = windows.Process32Next(snap, &pe) {
		entries[int(pe.ProcessID)] = snapshotEntry{
			parent: int(pe.ParentProcessID),
			exe:    windows.UTF16ToString(pe.ExeFile[:]),
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, err
	}
	return entries, nil
}

func creationTime(pid int) (uint64, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid)) //nolint:gosec // Windows PIDs are 32-bit
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h) //nolint:errcheck // query-only handle
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}

func readProcessInfo(pid int) (Process, error) {
	entries, err := snapshotProcesses()
	if err != nil {
		return Process{}, err
	}
	e, ok := entries[pid]
	if !ok {
		return Process{}, errors.New("process not found")
	}
	start, err := creationTime(pid)
	if err != nil {
		return Process{}, err
	}
	return Process{PID: pid, Start: start, Names: uniqueNames(e.exe)}, nil
}

// processChain walks one snapshot. Windows keeps a dead parent's PID in the
// child's entry, so a parent created after its child is a reused PID and
// ends the walk.
func processChain() []Process {
	entries, err := snapshotProcesses()
	if err != nil {
		return nil
	}
	var chain []Process
	pid := os.Getpid()
	var childStart uint64
	for i := 0; i < maxAncestry && pid > 0; i++ {
		e, ok := entries[pid]
		if !ok {
			break
		}
		start, err := creationTime(pid)
		if err != nil || (i > 0 && start > childStart) {
			break
		}
		chain = append(chain, Process{PID: pid, Start: start, Names: uniqueNames(e.exe)})
		if e.parent == pid {
			break
		}
		pid, childStart = e.parent, start
	}
	return chain
}
