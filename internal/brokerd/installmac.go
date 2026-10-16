package brokerd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
)

// Locations of the macOS broker, relative to the host root.
const (
	MacBrokerLabel   = "dev.keylatch.broker"
	MacPresenceLabel = "dev.keylatch.presence"
	// MacAccount is the service account the LaunchDaemon runs under.
	MacAccount = "_keylatch"

	macDaemonPlist   = "Library/LaunchDaemons/" + MacBrokerLabel + ".plist"
	macPresencePlist = "Library/LaunchAgents/" + MacPresenceLabel + ".plist"
	macLibexec       = "usr/local/libexec/keylatch"
	macStateDir      = "var/db/keylatch"
	macPresenceApp   = macLibexec + "/Keylatch Presence.app/Contents/MacOS/keylatch-presence"
	macFirstSvcID    = 300
	macLastSvcID     = 399
)

// MacInstaller puts the broker on a Mac: the _keylatch account, the state
// directory it owns, the device root in the System keychain, and the
// LaunchDaemon, then starts it. It never replaces an existing device root.
type MacInstaller struct {
	// Root is the filesystem root; "/" on a real host.
	Root string
	// Files holds the property lists (macospkg.Files).
	Files fs.FS
	Run   Runner
	Euid  func() int
	Rand  io.Reader
	Out   io.Writer
	// Own hands a path to the service account; nil leaves ownership alone
	// (tests run unprivileged).
	Own func(path string) error
	// RootStore keeps the device root; it receives the daemon path and the
	// ownership hook.
	RootStore func(stateDir, daemon string, own func(string) error) keys.RootStore
}

func (in *MacInstaller) path(rel string) string { return filepath.Join(in.Root, rel) }

// Install runs the installation. It is safe to run again.
func (in *MacInstaller) Install(ctx context.Context) (InstallResult, error) {
	var res InstallResult
	if in.Euid() != 0 {
		return res, ErrNotRoot
	}
	run := func(name string, args ...string) ([]byte, error) {
		res.Commands = append(res.Commands, strings.Join(append([]string{name}, args...), " "))
		return in.Run.Run(ctx, nil, name, args...)
	}
	daemon := in.path(macLibexec + "/keylatchd")
	if info, err := os.Stat(daemon); err != nil || info.IsDir() {
		return res, fmt.Errorf("the keylatchd binary is not at /%s: install the Keylatch package first", macLibexec)
	}
	if err := in.ensureAccount(ctx, run); err != nil {
		return res, err
	}
	state := in.path(macStateDir)
	for _, d := range []string{state, filepath.Join(state, "run")} {
		if err := os.MkdirAll(d, 0o755); err != nil { //nolint:gosec // G301: users traverse run/ to reach the socket
			return res, err
		}
		if in.Own != nil {
			if err := in.Own(d); err != nil {
				return res, fmt.Errorf("give %s to %s: %w", d, MacAccount, err)
			}
		}
	}
	store := in.RootStore
	if store == nil {
		store = defaultRootStore
	}
	rootStore := store(state, "/"+macLibexec+"/keylatchd", in.Own)
	created, err := rootStore.Create(in.Rand)
	if err != nil {
		return res, fmt.Errorf("create the device root: %w", err)
	}
	if created {
		res.RootCreated = true
		res.Written = append(res.Written, "device root ("+rootStore.Name()+")")
	} else {
		res.Kept = append(res.Kept, "device root")
	}
	for _, p := range []struct{ src, dest string }{
		{MacBrokerLabel + ".plist", macDaemonPlist},
		{MacPresenceLabel + ".plist", macPresencePlist},
	} {
		body, err := fs.ReadFile(in.Files, p.src)
		if err != nil {
			return res, err
		}
		if err := in.write(&res, p.dest, body); err != nil {
			return res, err
		}
	}
	if _, err := run("launchctl", "print", "system/"+MacBrokerLabel); err != nil {
		if _, err := run("launchctl", "bootstrap", "system", in.path(macDaemonPlist)); err != nil {
			return res, fmt.Errorf("load the LaunchDaemon: %w", err)
		}
	} else if _, err := run("launchctl", "kickstart", "-k", "system/"+MacBrokerLabel); err != nil {
		return res, fmt.Errorf("restart the LaunchDaemon: %w", err)
	}
	if _, err := run("launchctl", "enable", "system/"+MacBrokerLabel); err != nil {
		return res, fmt.Errorf("enable the LaunchDaemon: %w", err)
	}
	return res, nil
}

// ensureAccount creates the _keylatch group and user unless they exist. Service
// accounts live below 500; the first free id in 300..399 is used for both.
func (in *MacInstaller) ensureAccount(ctx context.Context, run func(string, ...string) ([]byte, error)) error {
	if _, err := run("dscl", ".", "-read", "/Users/"+MacAccount, "UniqueID"); err == nil {
		return nil
	}
	list, err := run("dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return fmt.Errorf("list accounts: %w", err)
	}
	groups, err := run("dscl", ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}
	id, err := freeServiceID(string(list), string(groups))
	if err != nil {
		return err
	}
	sid := strconv.Itoa(id)
	for _, c := range [][]string{
		{".", "-create", "/Groups/" + MacAccount},
		{".", "-create", "/Groups/" + MacAccount, "PrimaryGroupID", sid},
		{".", "-create", "/Groups/" + MacAccount, "RealName", "Keylatch broker"},
		{".", "-create", "/Users/" + MacAccount},
		{".", "-create", "/Users/" + MacAccount, "UniqueID", sid},
		{".", "-create", "/Users/" + MacAccount, "PrimaryGroupID", sid},
		{".", "-create", "/Users/" + MacAccount, "UserShell", "/usr/bin/false"},
		{".", "-create", "/Users/" + MacAccount, "RealName", "Keylatch broker"},
		{".", "-create", "/Users/" + MacAccount, "NFSHomeDirectory", "/var/empty"},
		{".", "-create", "/Users/" + MacAccount, "IsHidden", "1"},
		{".", "-create", "/Users/" + MacAccount, "Password", "*"},
	} {
		if _, err := run("dscl", c...); err != nil {
			return fmt.Errorf("create the %s account: %w", MacAccount, err)
		}
	}
	return nil
}

// freeServiceID returns the lowest id in the service range that no listed user
// or group holds. Each listing is "name id" per line.
func freeServiceID(users, groups string) (int, error) {
	taken := map[int]bool{}
	for _, listing := range []string{users, groups} {
		for _, line := range strings.Split(listing, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			if n, err := strconv.Atoi(f[len(f)-1]); err == nil {
				taken[n] = true
			}
		}
	}
	for id := macFirstSvcID; id <= macLastSvcID; id++ {
		if !taken[id] {
			return id, nil
		}
	}
	return 0, errors.New("no free service account id between 300 and 399")
}

// write installs body at dest unless identical content is already there. The
// property list must be root-owned and not writable by others, or launchd
// refuses it.
func (in *MacInstaller) write(res *InstallResult, dest string, body []byte) error {
	full := in.path(dest)
	if cur, err := os.ReadFile(full); err == nil && bytes.Equal(cur, body) { //nolint:gosec // G304: a path under the installer's root
		res.Kept = append(res.Kept, dest)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec // G301: system directories
		return err
	}
	if err := os.WriteFile(full, body, 0o644); err != nil { //nolint:gosec // G306: launchd requires a world-readable, root-owned plist
		return err
	}
	res.Written = append(res.Written, dest)
	return nil
}

// EnrollPresence registers the Secure Enclave key of a user with the daemon.
// It runs the presence helper inside the user's login session, which creates
// the key if it does not exist and prints the public half; root writes that
// key where the daemon reads it. Only root enrolls, so a client of the daemon
// cannot register a key of its own.
func EnrollPresence(ctx context.Context, run Runner, euid func() int, stateRoot string, uid uint32) (string, error) {
	if euid() != 0 {
		return "", ErrNotRoot
	}
	helper := "/" + macPresenceApp
	out, err := run.Run(ctx, nil, "launchctl", "asuser", uidString(uid), helper, "public-key")
	if err != nil {
		return "", fmt.Errorf("ask the presence helper for its key: %w", err)
	}
	dk := DirKeys{Dir: filepath.Join(stateRoot, "presence")}
	if err := dk.Enroll(uid, bytes.TrimSpace(out)); err != nil {
		return "", err
	}
	return dk.Path(uid), nil
}

// MacUninstallCommands lists what removes the broker; the CLI prints them.
func MacUninstallCommands() []string {
	return []string{
		"launchctl bootout system/" + MacBrokerLabel,
		"rm /" + macDaemonPlist,
		"rm /" + macPresencePlist,
	}
}
