package contained

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// SeatbeltParams is everything the macOS profile depends on. The paths are
// resolved real paths: Seatbelt matches the path the kernel resolved, so a
// symlink such as /tmp would never match.
type SeatbeltParams struct {
	// Project is the read-write project directory.
	Project string
	// ReadOnly and ReadWrite are further directories the child may use.
	ReadOnly  []string
	ReadWrite []string
	// Home and Tmp are the child's private home and temporary directories.
	Home string
	Tmp  string
	// ProxyPort and ConnectPorts are the only loopback ports the child may
	// connect to.
	ProxyPort    int
	ConnectPorts []int
}

// systemReadOnly are the host directories every command needs to run. The
// user's home directory, the Keychain files and /Volumes are not among them.
var systemReadOnly = []string{
	"/usr", "/bin", "/sbin", "/System", "/Library", "/Applications/Xcode.app", "/Library/Developer",
	"/opt/homebrew", "/private/etc", "/private/var/db/dyld", "/private/var/select", "/dev",
}

// machServices are the system services a command-line tool needs. The
// security daemon, the pasteboard and the window server are left out: the
// first would give the child the user's Keychain.
var machServices = []string{
	"com.apple.system.opendirectoryd.libinfo", "com.apple.system.notification_center",
	"com.apple.logd", "com.apple.diagnosticd", "com.apple.system.logger",
	"com.apple.cfprefsd.daemon", "com.apple.trustd", "com.apple.trustd.agent",
}

// SeatbeltProfile renders the sandbox-exec profile for one contained run: file
// access limited to the listed directories, no network except the proxy
// forwarder on loopback, and no other process or IPC reach.
func SeatbeltProfile(p SeatbeltParams) (string, error) {
	if p.Project == "" || p.Home == "" || p.Tmp == "" {
		return "", errors.New("contained: the project, home and temporary directories are required")
	}
	var b strings.Builder
	b.WriteString("(version 1)\n(deny default)\n")
	b.WriteString("(allow process-fork)\n(allow process-exec)\n(allow signal (target self))\n")
	b.WriteString("(allow sysctl-read)\n(allow file-read-metadata)\n(allow file-read* (literal \"/\"))\n")
	for _, s := range machServices {
		fmt.Fprintf(&b, "(allow mach-lookup (global-name %s))\n", mustQuote(s))
	}
	b.WriteString("(allow file-write* (literal \"/dev/null\") (literal \"/dev/dtracehelper\"))\n")
	if err := writeRule(&b, "file-read*", append(append([]string{}, systemReadOnly...), p.ReadOnly...)); err != nil {
		return "", err
	}
	if err := writeRule(&b, "file-read* file-write*", append([]string{p.Project, p.Home, p.Tmp}, p.ReadWrite...)); err != nil {
		return "", err
	}
	b.WriteString("(deny network*)\n")
	for _, port := range append([]int{p.ProxyPort}, p.ConnectPorts...) {
		if port < 1 || port > 65535 {
			return "", fmt.Errorf("contained: port %d is out of range", port)
		}
		fmt.Fprintf(&b, "(allow network-outbound (remote ip %s))\n", mustQuote("localhost:"+strconv.Itoa(port)))
	}
	b.WriteString("(allow network-bind (local ip \"localhost:*\"))\n(allow network-inbound (local ip \"localhost:*\"))\n")
	return b.String(), nil
}

func writeRule(b *strings.Builder, ops string, paths []string) error {
	b.WriteString("(allow " + ops)
	for _, p := range paths {
		q, err := quoteSBPL(p)
		if err != nil {
			return err
		}
		// Profiles are macOS paths, so the check must not depend on the host OS.
		if !path.IsAbs(p) {
			return fmt.Errorf("contained: %q must be an absolute path", p)
		}
		b.WriteString(" (subpath " + q + ")")
	}
	b.WriteString(")\n")
	return nil
}

// quoteSBPL quotes s as a profile string literal. Control characters have no
// safe spelling, so a path that holds one is refused.
func quoteSBPL(s string) (string, error) {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("contained: %q has a control character", s)
		}
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`, nil
}

func mustQuote(s string) string {
	q, err := quoteSBPL(s)
	if err != nil {
		panic(err)
	}
	return q
}

// seatbeltReport is the macOS capability report given the result of looking
// for sandbox-exec.
func seatbeltReport(statErr error) Report {
	seatbelt := Capability{Name: "seatbelt", OK: statErr == nil, Detail: "sandbox-exec is present"}
	if statErr != nil {
		seatbelt.Detail = statErr.Error()
	}
	r := Report{Backend: "seatbelt", Capabilities: []Capability{
		seatbelt,
		{Name: "limits", Detail: "memory, process and CPU limits are not applied on macOS"},
		{Name: "terminal", Detail: "terminal runs are not supported on macOS"},
	}}
	r.Supported = len(r.Missing()) == 0
	return r
}

// hostDirs are the private directories of a run that has no mount namespace:
// the empty home and the temporary directory live under Spec.RootDir.
func hostDirs(spec Spec) (home, tmp string) {
	return filepath.Join(spec.RootDir, "home"), filepath.Join(spec.RootDir, "tmp")
}

// seatbeltParams derives the profile inputs from spec. resolve returns the real
// path of a directory, or "" when it does not exist, and such paths are skipped.
func seatbeltParams(spec Spec, resolve func(string) string) SeatbeltParams {
	home, tmp := hostDirs(spec)
	keep := func(paths []string) []string {
		var out []string
		for _, p := range paths {
			if r := resolve(p); r != "" {
				out = append(out, r)
			}
		}
		return out
	}
	return SeatbeltParams{
		Project: resolve(spec.Project), ReadOnly: keep(spec.ReadOnly), ReadWrite: keep(spec.ReadWrite),
		Home: resolve(home), Tmp: resolve(tmp), ProxyPort: spec.ProxyPort, ConnectPorts: spec.ConnectPorts,
	}
}

// hostEnv points the child's HOME and temporary directory at the private ones.
func hostEnv(spec Spec) []string {
	home, tmp := hostDirs(spec)
	return replaceEnv(replaceEnv(spec.Env, "HOME", home), "TMPDIR", tmp)
}

// sandboxExecArgs is the sandbox-exec command line that runs argv under profile.
func sandboxExecArgs(profile, target string, argv []string) []string {
	return append([]string{"-p", profile, "--", target}, argv[1:]...)
}
