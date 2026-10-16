package contained

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"unicode/utf16"
)

// jobPlan is what the Windows job object enforces on a run.
type jobPlan struct {
	// ProcessMemory caps each process, in bytes; zero is unlimited.
	ProcessMemory uint64
	// ActiveProcesses caps the processes alive at once; zero is unlimited.
	ActiveProcesses uint32
	// CPURate is a hard cap in hundredths of a percent of the whole machine;
	// zero is unlimited.
	CPURate uint32
}

// planJob turns Limits into job object settings. A run always dies with its
// job; that and the UI restrictions are not optional and are set by the caller.
func planJob(l Limits, cpus int) jobPlan {
	p := jobPlan{}
	if l.MemoryBytes > 0 {
		p.ProcessMemory = uint64(l.MemoryBytes)
	}
	if l.PIDs > 0 {
		p.ActiveProcesses = uint32(l.PIDs) //nolint:gosec // G115: a process count far below 2^32
	}
	if l.CPUPercent > 0 && cpus > 0 {
		rate := l.CPUPercent * 100 / cpus
		p.CPURate = uint32(min(max(rate, 1), 10000)) //nolint:gosec // G115: clamped to 1..10000
	}
	return p
}

// appContainerName names the profile of one daemon's runs. It is derived from
// the private root directory so two daemons never share a profile.
func appContainerName(rootDir string) string {
	sum := sha256.Sum256([]byte(rootDir))
	return "keylatch.contained." + hex.EncodeToString(sum[:8])
}

// aclGrant is one directory the AppContainer is given access to.
type aclGrant struct {
	Path  string
	Write bool
}

// planGrants lists the directories the AppContainer needs beyond the system
// ones every AppContainer can already read.
func planGrants(spec Spec, home, tmp string) []aclGrant {
	grants := []aclGrant{{spec.Project, true}, {home, true}, {tmp, true}}
	for _, p := range spec.ReadWrite {
		grants = append(grants, aclGrant{p, true})
	}
	for _, p := range spec.ReadOnly {
		grants = append(grants, aclGrant{p, false})
	}
	return grants
}

// composeCommandLine quotes args the way the Windows C runtime parses them back.
func composeCommandLine(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = quoteWindowsArg(a)
	}
	return strings.Join(parts, " ")
}

func quoteWindowsArg(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n\v\"") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			slashes++
			b.WriteRune(r)
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes+1))
			b.WriteRune(r)
			slashes = 0
		default:
			slashes = 0
			b.WriteRune(r)
		}
	}
	b.WriteString(strings.Repeat(`\`, slashes))
	b.WriteByte('"')
	return b.String()
}

// envBlock encodes env as a Windows environment block: UTF-16, sorted by name
// without regard to case, each entry and the block ended by a NUL.
func envBlock(env []string) []uint16 {
	sorted := append([]string{}, env...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return strings.ToUpper(sorted[i]) < strings.ToUpper(sorted[j])
	})
	var out []uint16
	for _, e := range sorted {
		out = append(out, utf16.Encode([]rune(e))...)
		out = append(out, 0)
	}
	if len(out) == 0 {
		out = append(out, 0)
	}
	return append(out, 0)
}

// appContainerReport is the Windows capability report given the results of
// probing for the AppContainer and job object APIs.
func appContainerReport(appContainerErr, jobErr error) Report {
	row := func(name string, err error, ok string) Capability {
		c := Capability{Name: name, OK: err == nil, Detail: ok}
		if err != nil {
			c.Detail = err.Error()
		}
		return c
	}
	r := Report{Backend: "appcontainer", Capabilities: []Capability{
		row("appcontainer", appContainerErr, "AppContainer profiles are available"),
		row("job_object", jobErr, "job objects are available"),
		{Name: "terminal", Detail: "terminal runs are not supported on Windows"},
	}}
	r.Supported = len(r.Missing()) == 0
	return r
}
