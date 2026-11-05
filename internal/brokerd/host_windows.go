package brokerd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
)

// cngKeyName is the machine key that seals the device root.
const cngKeyName = "KeylatchDeviceRoot"

// NewWindowsHost returns the machine the installer runs on.
func NewWindowsHost() WinHost { return windowsHost{} }

type windowsHost struct{}

func (windowsHost) Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

func (windowsHost) Binary(name string) (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	p := filepath.Join(filepath.Dir(self), name)
	if info, err := os.Stat(p); err != nil || info.IsDir() {
		return "", fmt.Errorf("%s is not installed next to %s", name, filepath.Base(self))
	}
	return p, nil
}

// SecureDir creates path and replaces its DACL with sddl, protected so nothing
// is inherited from ProgramData.
func (windowsHost) SecureDir(path, sddl string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func (windowsHost) ServiceExists(name string) (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return false, nil
		}
		return false, err
	}
	_ = s.Close()
	return true, nil
}

func (windowsHost) CreateService(spec ServiceSpec) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.CreateService(spec.Name, spec.Exe, mgr.Config{
		DisplayName:      spec.Display,
		Description:      spec.Description,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: spec.Account,
		SidType:          windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}, spec.Args...)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	return s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 2 * time.Second}}, 86400)
}

func (windowsHost) StartService(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer func() { _ = m.Disconnect() }()
	s, err := m.OpenService(name)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return nil
}

func (windowsHost) RootStore(adminDir string) keys.RootStore {
	return keys.SealedFile{
		Path:   filepath.Join(adminDir, "root.sealed"),
		Sealer: keys.CNGSealer{KeyName: cngKeyName, ServiceSID: ServiceSID(WindowsServiceName)},
	}
}

func (windowsHost) ResolveSID(account string) (string, error) {
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}
