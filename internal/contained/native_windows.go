//nolint:gosec // G103, G115: every unsafe pointer and size here is a Win32 argument for a struct of this package.
package contained

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	procThreadAttributeHandleList           = 0x00020002
	procThreadAttributeSecurityCapabilities = 0x00020009
	errorAlreadyExists                      = 0x800700B7
	jobObjectCPUEnable                      = 0x1
	jobObjectCPUHardCap                     = 0x4
	uiLimits                                = windows.JOB_OBJECT_UILIMIT_DESKTOP | windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
		windows.JOB_OBJECT_UILIMIT_EXITWINDOWS | windows.JOB_OBJECT_UILIMIT_GLOBALATOMS | windows.JOB_OBJECT_UILIMIT_HANDLES |
		windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD
)

var (
	userenv         = windows.NewLazySystemDLL("userenv.dll")
	createProfile   = userenv.NewProc("CreateAppContainerProfile")
	deriveSID       = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
	deleteProfile   = userenv.NewProc("DeleteAppContainerProfile")
	firewallapi     = windows.NewLazySystemDLL("firewallapi.dll")
	netIsoGetConfig = firewallapi.NewProc("NetworkIsolationGetAppContainerConfig")
	netIsoSetConfig = firewallapi.NewProc("NetworkIsolationSetAppContainerConfig")
	netIsoFree      = firewallapi.NewProc("NetworkIsolationFreeAppContainers")
	createJob       = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateJobObjectW")
)

type securityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    *windows.SIDAndAttributes
	CapabilityCount uint32
	Reserved        uint32
}

type cpuRateControl struct {
	ControlFlags uint32
	CPURate      uint32
}

// Probe reports whether the AppContainer and job object APIs are present.
func Probe() Report {
	return appContainerReport(createProfile.Find(), createJob.Find())
}

type winChild struct {
	process windows.Handle
	job     windows.Handle
	stdin   *os.File
	stdout  *os.File
	stderr  *os.File
	done    chan struct{}
	exit    int
	err     error
	cleanup func()
	once    sync.Once
}

// Start launches spec in an AppContainer that holds no capabilities, inside a
// job object that bounds it. An AppContainer cannot reach the network or other
// users' files unless granted; the loopback exemption and the directory grants
// below are everything the child is given.
func (n *Native) Start(spec Spec) (Child, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	if spec.TTY != nil {
		return nil, errors.New("contained: terminal runs are not supported on Windows")
	}
	home, tmp := hostDirs(spec)
	for _, d := range []string{home, tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	if err := writeHoney(home, spec.Honey); err != nil {
		return nil, err
	}
	env := hostEnv(spec)
	target, err := lookPathIn(env, spec.Argv[0], []string{".exe", ".com"})
	if err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spec.ProxyPort))
	if err != nil {
		return nil, fmt.Errorf("contained: the proxy port %d is in use: %w", spec.ProxyPort, err)
	}
	egress := filepath.Join(spec.EgressDir, EgressSocket)
	go Forward(l, func() (net.Conn, error) { return net.Dial("unix", egress) })

	var undo []func()
	cleanup := func() {
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
		_ = l.Close()
		_ = os.RemoveAll(home)
		_ = os.RemoveAll(tmp)
	}
	c, err := startAppContainer(spec, target, env, home, tmp, &undo)
	if err != nil {
		cleanup()
		return nil, err
	}
	c.cleanup = cleanup
	go c.wait()
	return c, nil
}

func startAppContainer(spec Spec, target string, env []string, home, tmp string, undo *[]func()) (_ *winChild, retErr error) {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	name := appContainerName(spec.RootDir) + "." + hex.EncodeToString(nonce[:])
	sid, err := createAppContainer(name)
	if err != nil {
		return nil, fmt.Errorf("contained: create the AppContainer: %w", err)
	}
	*undo = append(*undo, func() { dropAppContainer(name) })
	if err := exemptLoopback(sid, undo); err != nil {
		return nil, fmt.Errorf("contained: allow loopback for the AppContainer (the service account is required): %w", err)
	}
	for _, g := range planGrants(spec, home, tmp) {
		if err := changeAccess(g.Path, sid, g.Write, windows.GRANT_ACCESS); err != nil {
			return nil, fmt.Errorf("contained: grant access to %s: %w", g.Path, err)
		}
		*undo = append(*undo, func() { _ = changeAccess(g.Path, sid, g.Write, windows.REVOKE_ACCESS) })
	}
	job, err := newJob(planJob(spec.Limits, runtime.NumCPU()))
	if err != nil {
		return nil, err
	}
	*undo = append(*undo, func() { _ = windows.CloseHandle(job) })

	// c is a local, not a named result: `return nil, err` clears a named result
	// before the deferred cleanup below runs.
	c := &winChild{job: job, done: make(chan struct{})}
	inR, inW, err := pipeEnds(false)
	if err != nil {
		return nil, err
	}
	outR, outW, err := pipeEnds(true)
	if err != nil {
		return nil, err
	}
	errR, errW, err := pipeEnds(true)
	if err != nil {
		return nil, err
	}
	c.stdin, c.stdout, c.stderr = os.NewFile(uintptr(inW), "stdin"), os.NewFile(uintptr(outR), "stdout"), os.NewFile(uintptr(errR), "stderr")
	childEnds := []windows.Handle{inR, outW, errW}
	defer func() {
		if retErr != nil {
			closeAll(c.stdin, c.stdout, c.stderr)
		}
		for _, h := range childEnds {
			_ = windows.CloseHandle(h)
		}
	}()

	caps := securityCapabilities{AppContainerSid: sid}
	al, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	defer al.Delete()
	if err := al.Update(procThreadAttributeSecurityCapabilities, unsafe.Pointer(&caps), unsafe.Sizeof(caps)); err != nil {
		return nil, err
	}
	if err := al.Update(procThreadAttributeHandleList, unsafe.Pointer(&childEnds[0]), unsafe.Sizeof(childEnds[0])*uintptr(len(childEnds))); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{ProcThreadAttributeList: al.List()}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput, si.StdOutput, si.StdErr = inR, outW, errW

	app, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return nil, err
	}
	cmdline, err := windows.UTF16PtrFromString(composeCommandLine(append([]string{target}, spec.Argv[1:]...)))
	if err != nil {
		return nil, err
	}
	dir, err := windows.UTF16PtrFromString(spec.Dir)
	if err != nil {
		return nil, err
	}
	block := envBlock(env)
	var pi windows.ProcessInformation
	flags := uint32(windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_SUSPENDED)
	if err := windows.CreateProcess(app, cmdline, nil, nil, true, flags, &block[0], dir, &si.StartupInfo, &pi); err != nil {
		return nil, fmt.Errorf("contained: start the sandbox: %w", err)
	}
	defer windows.CloseHandle(pi.Thread) //nolint:errcheck
	c.process = pi.Process
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
		return nil, fmt.Errorf("contained: place the process in its job: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = windows.CloseHandle(pi.Process)
		return nil, err
	}
	return c, nil
}

// pipeEnds makes a pipe whose child end is inheritable; parentReads says which
// end the child writes. It returns (read, write) handles.
func pipeEnds(parentReads bool) (r, w windows.Handle, err error) {
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if err = windows.CreatePipe(&r, &w, &sa, 0); err != nil {
		return 0, 0, err
	}
	parent := w
	if parentReads {
		parent = r
	}
	if err = windows.SetHandleInformation(parent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		_ = windows.CloseHandle(r)
		_ = windows.CloseHandle(w)
	}
	return r, w, err
}

func createAppContainer(name string) (*windows.SID, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	hr, _, _ := createProfile.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), 0, 0, uintptr(unsafe.Pointer(&sid)))
	if hr == 0 {
		return sid, nil
	}
	if hr != errorAlreadyExists {
		return nil, fmt.Errorf("CreateAppContainerProfile: HRESULT %#x", hr)
	}
	if hr, _, _ = deriveSID.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&sid))); hr != 0 {
		return nil, fmt.Errorf("DeriveAppContainerSidFromAppContainerName: HRESULT %#x", hr)
	}
	return sid, nil
}

func dropAppContainer(name string) {
	if n, err := windows.UTF16PtrFromString(name); err == nil {
		_, _, _ = deleteProfile.Call(uintptr(unsafe.Pointer(n)))
	}
}

// exemptLoopback lets the AppContainer reach 127.0.0.1, which is blocked for
// every AppContainer by default. The system keeps one list of exempt
// containers, so the list is read, extended and written back.
func exemptLoopback(sid *windows.SID, undo *[]func()) error {
	list, err := loopbackExempt()
	if err != nil {
		return err
	}
	if err := setLoopbackExempt(append(list, windows.SIDAndAttributes{Sid: sid})); err != nil {
		return err
	}
	*undo = append(*undo, func() {
		cur, err := loopbackExempt()
		if err != nil {
			return
		}
		kept := cur[:0]
		for _, e := range cur {
			if !e.Sid.Equals(sid) {
				kept = append(kept, e)
			}
		}
		_ = setLoopbackExempt(kept)
	})
	return nil
}

func loopbackExempt() ([]windows.SIDAndAttributes, error) {
	var n uint32
	var p *windows.SIDAndAttributes
	if r, _, _ := netIsoGetConfig.Call(uintptr(unsafe.Pointer(&n)), uintptr(unsafe.Pointer(&p))); r != 0 {
		return nil, fmt.Errorf("NetworkIsolationGetAppContainerConfig: error %d", r)
	}
	if p == nil || n == 0 {
		return nil, nil
	}
	defer netIsoFree.Call(uintptr(unsafe.Pointer(p))) //nolint:errcheck
	// The list is copied: the system's buffer is freed on return.
	return append([]windows.SIDAndAttributes(nil), unsafe.Slice(p, n)...), nil
}

func setLoopbackExempt(list []windows.SIDAndAttributes) error {
	var p *windows.SIDAndAttributes
	if len(list) > 0 {
		p = &list[0]
	}
	if r, _, _ := netIsoSetConfig.Call(uintptr(len(list)), uintptr(unsafe.Pointer(p))); r != 0 {
		return fmt.Errorf("NetworkIsolationSetAppContainerConfig: error %d", r)
	}
	return nil
}

// changeAccess grants or revokes the AppContainer's access to a directory tree.
func changeAccess(path string, sid *windows.SID, write bool, mode windows.ACCESS_MODE) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	perm := uint32(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE)
	if write {
		perm |= windows.FILE_GENERIC_WRITE | windows.DELETE
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.ACCESS_MASK(perm),
		AccessMode:        mode,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, dacl)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, merged, nil)
}

// newJob creates the job object that bounds the run and ends it when closed.
func newJob(plan jobPlan) (windows.Handle, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("contained: create the job object: %w", err)
	}
	var ext windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	ext.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if plan.ProcessMemory > 0 {
		ext.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY
		ext.ProcessMemoryLimit = uintptr(plan.ProcessMemory)
	}
	if plan.ActiveProcesses > 0 {
		ext.BasicLimitInformation.LimitFlags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		ext.BasicLimitInformation.ActiveProcessLimit = plan.ActiveProcesses
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: uiLimits}
	steps := []struct {
		class uint32
		info  unsafe.Pointer
		size  uintptr
	}{
		{windows.JobObjectExtendedLimitInformation, unsafe.Pointer(&ext), unsafe.Sizeof(ext)},
		{windows.JobObjectBasicUIRestrictions, unsafe.Pointer(&ui), unsafe.Sizeof(ui)},
	}
	if plan.CPURate > 0 {
		cpu := cpuRateControl{ControlFlags: jobObjectCPUEnable | jobObjectCPUHardCap, CPURate: plan.CPURate}
		steps = append(steps, struct {
			class uint32
			info  unsafe.Pointer
			size  uintptr
		}{windows.JobObjectCpuRateControlInformation, unsafe.Pointer(&cpu), unsafe.Sizeof(cpu)})
	}
	for _, s := range steps {
		if _, err := windows.SetInformationJobObject(h, s.class, uintptr(s.info), uint32(s.size)); err != nil {
			_ = windows.CloseHandle(h)
			return 0, fmt.Errorf("contained: configure the job object: %w", err)
		}
	}
	return h, nil
}

func (c *winChild) wait() {
	_, _ = windows.WaitForSingleObject(c.process, windows.INFINITE)
	var code uint32
	c.err = windows.GetExitCodeProcess(c.process, &code)
	c.exit = int(code)
	// A run that leaves processes behind does not outlive its job.
	_ = windows.TerminateJobObject(c.job, uint32(code))
	_ = windows.CloseHandle(c.process)
	c.once.Do(c.cleanup)
	close(c.done)
}

func (c *winChild) Stdin() io.WriteCloser { return c.stdin }
func (c *winChild) Stdout() io.Reader     { return c.stdout }
func (c *winChild) Stderr() io.Reader     { return c.stderr }

func (*winChild) Resize(uint16, uint16) error {
	return errors.New("contained: the run has no terminal")
}

// Signal ends the run: Windows has no signals, so any signal terminates the job
// and the exit status is 128 plus its number, as for a signalled Unix process.
func (c *winChild) Signal(sig int) error {
	return windows.TerminateJobObject(c.job, uint32(128+sig)) //nolint:gosec // G115: a small signal number
}

func (c *winChild) Kill() { _ = windows.TerminateJobObject(c.job, 128+9) }

func (c *winChild) Wait() (int, error) {
	<-c.done
	return c.exit, c.err
}
