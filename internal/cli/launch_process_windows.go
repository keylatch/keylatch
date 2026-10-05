//go:build windows

package cli

import (
	"fmt"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// startLaunchProcess starts the harness inside a job object so that stopping
// it also stops every process it started. The job is created with
// kill-on-close, so the tree also dies if launch itself is killed. The harness
// is assigned to the job right after it starts; a process it spawns before
// that is outside the job.
func startLaunchProcess(cmd *exec.Cmd) (func() error, error) {
	job, err := newLaunchJob()
	if err != nil {
		return nil, err
	}
	var once sync.Once
	var stopErr error
	stop := func() error {
		once.Do(func() {
			stopErr = windows.TerminateJobObject(job, 1)
			if err := windows.CloseHandle(job); stopErr == nil {
				stopErr = err
			}
		})
		return stopErr
	}
	cmd.Cancel = stop
	if err := cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	if err := assignLaunchJob(job, cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = windows.CloseHandle(job)
		return nil, err
	}
	return stop, nil
}

func newLaunchJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { //nolint:gosec // documented Win32 struct pointer
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("configure job object: %w", err)
	}
	return job, nil
}

// assignLaunchJob opens the harness by pid; exec.Cmd still holds its handle,
// so the pid cannot have been reused.
func assignLaunchJob(job windows.Handle, pid int) error {
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid)) //nolint:gosec // Windows PIDs are 32-bit
	if err != nil {
		return fmt.Errorf("open agent process: %w", err)
	}
	defer func() { _ = windows.CloseHandle(proc) }()
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		return fmt.Errorf("assign agent to job object: %w", err)
	}
	return nil
}

func restoreLaunchTerminal(*exec.Cmd) error { return nil }

func launchExitCode(err *exec.ExitError) int {
	if code := err.ExitCode(); code >= 0 {
		return code
	}
	return 1
}
