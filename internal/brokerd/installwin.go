package brokerd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
)

// Names of the Windows broker.
const (
	// WindowsServiceName is the service, which runs as NT SERVICE\keylatch.
	WindowsServiceName = "keylatch"
	// WindowsAdminDirName holds what an administrator manages and the service
	// only reads: the public presence keys and the CNG-sealed device root. It
	// sits next to (not inside) the service-only state directory, because the
	// administrator cannot enter that one. The sealed root opens only with the
	// CNG key, whose ACL names the service.
	WindowsAdminDirName = "keylatch-admin"
	windowsRunKey       = `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
)

// AdminDir returns the administrator-managed directory next to state.
func AdminDir(state string) string { return filepath.Join(filepath.Dir(state), WindowsAdminDirName) }

// ErrNotAdmin means the installer was not run from an elevated prompt.
var ErrNotAdmin = errors.New("broker install changes system settings and needs an administrator: run it from an elevated prompt")

// ServiceSpec describes the service the installer registers.
type ServiceSpec struct {
	Name        string
	Display     string
	Description string
	Exe         string
	Args        []string
	// Account is the service account; NT SERVICE\<name> is a virtual account
	// with no password.
	Account string
}

// WinHost is what the Windows installer needs from the machine. The real host
// calls the service control manager, the security APIs and CNG; tests replace
// it.
type WinHost interface {
	Elevated() bool
	// Binary returns the path of an installed Keylatch binary.
	Binary(name string) (string, error)
	// SecureDir creates path and applies sddl as its protected DACL.
	SecureDir(path, sddl string) error
	ServiceExists(name string) (bool, error)
	CreateService(ServiceSpec) error
	StartService(name string) error
	// RootStore returns the CNG-sealed device root stored in adminDir.
	RootStore(adminDir string) keys.RootStore
	// ResolveSID returns the SID of an account name.
	ResolveSID(account string) (string, error)
}

// WindowsInstaller puts the broker on a Windows host: the state directory with
// a service-only ACL, the device root sealed by a CNG key, the service, and the
// presence helper's logon entry. It never replaces an existing device root.
type WindowsInstaller struct {
	Host WinHost
	Run  Runner
	// StateRoot defaults to DefaultStateRoot; AdminRoot to AdminDir(StateRoot).
	StateRoot string
	AdminRoot string
	Rand      io.Reader
	Out       io.Writer
}

// Install runs the installation. It is safe to run again.
func (in *WindowsInstaller) Install(ctx context.Context) (InstallResult, error) {
	var res InstallResult
	if !in.Host.Elevated() {
		return res, ErrNotAdmin
	}
	state := in.StateRoot
	if state == "" {
		state = DefaultStateRoot
	}
	admin := in.AdminRoot
	if admin == "" {
		admin = AdminDir(state)
	}
	daemon, err := in.Host.Binary("keylatchd.exe")
	if err != nil {
		return res, fmt.Errorf("find keylatchd: %w", err)
	}
	svcSID := ServiceSID(WindowsServiceName)
	if err := in.Host.SecureDir(state, DirSDDL(svcSID)); err != nil {
		return res, fmt.Errorf("secure %s: %w", state, err)
	}
	res.Written = append(res.Written, state)
	if err := in.Host.SecureDir(admin, AdminDirSDDL(svcSID)); err != nil {
		return res, fmt.Errorf("secure %s: %w", admin, err)
	}
	res.Written = append(res.Written, admin)

	store := in.Host.RootStore(admin)
	created, err := store.Create(in.Rand)
	if err != nil {
		return res, fmt.Errorf("create the device root: %w", err)
	}
	if created {
		res.RootCreated = true
		res.Written = append(res.Written, "device root ("+store.Name()+")")
	} else {
		res.Kept = append(res.Kept, "device root")
	}

	exists, err := in.Host.ServiceExists(WindowsServiceName)
	if err != nil {
		return res, err
	}
	if exists {
		res.Kept = append(res.Kept, "service "+WindowsServiceName)
	} else {
		if err := in.Host.CreateService(ServiceSpec{
			Name:        WindowsServiceName,
			Display:     "Keylatch broker",
			Description: "Holds the Keylatch key hierarchy, secret store, policy and audit log for the users of this machine.",
			Exe:         daemon,
			Args:        []string{"broker", "--service", "--state", state},
			Account:     `NT SERVICE\` + WindowsServiceName,
		}); err != nil {
			return res, fmt.Errorf("create the service: %w", err)
		}
		res.Written = append(res.Written, "service "+WindowsServiceName)
	}
	if err := in.Host.StartService(WindowsServiceName); err != nil {
		return res, fmt.Errorf("start the service: %w", err)
	}

	if helper, err := in.Host.Binary("keylatch-presence.exe"); err == nil {
		value := `"` + helper + `" serve`
		args := []string{"add", windowsRunKey, "/v", "KeylatchPresence", "/t", "REG_SZ", "/d", value, "/f"}
		res.Commands = append(res.Commands, strings.Join(append([]string{"reg"}, args...), " "))
		if _, err := in.Run.Run(ctx, nil, "reg", args...); err != nil {
			return res, fmt.Errorf("register the presence helper at logon: %w", err)
		}
		res.Written = append(res.Written, "presence helper logon entry")
	} else {
		res.Kept = append(res.Kept, "presence helper (not installed)")
	}
	return res, nil
}

// AdminDirSDDL lets SYSTEM and administrators manage the public presence keys
// and the sealed root, and gives the service read access.
func AdminDirSDDL(serviceSID string) string {
	return "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;" + serviceSID + ")"
}

// EnrollWindows registers a user's Windows Hello key. An administrator
// enrolls; the key lives under the account's SID.
func EnrollWindows(host WinHost, adminRoot, account string, pemBytes []byte) (string, error) {
	if !host.Elevated() {
		return "", ErrNotAdmin
	}
	sid, err := host.ResolveSID(account)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", account, err)
	}
	if !IsUserSID(sid) {
		return "", fmt.Errorf("%w: %s", ErrNotUser, sid)
	}
	dk := DirKeys{Dir: filepath.Join(adminRoot, "presence")}
	if err := dk.EnrollNamed(sid, pemBytes); err != nil {
		return "", err
	}
	return dk.PathOf(sid), nil
}
