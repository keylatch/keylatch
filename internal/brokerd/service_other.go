//go:build !windows

package brokerd

import (
	"context"
	"errors"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
)

// IsWindowsService is false off Windows.
func IsWindowsService() bool { return false }

// RunService is unavailable off Windows.
func RunService(string, func(context.Context) error) error {
	return errors.New("brokerd: Windows services only exist on Windows")
}

// NewWindowsHost returns a host that cannot install anything.
func NewWindowsHost() WinHost { return unsupportedHost{} }

type unsupportedHost struct{}

var errNotWindows = errors.New("brokerd: the Windows installer only runs on Windows")

func (unsupportedHost) Elevated() bool                     { return false }
func (unsupportedHost) Binary(string) (string, error)      { return "", errNotWindows }
func (unsupportedHost) SecureDir(string, string) error     { return errNotWindows }
func (unsupportedHost) ServiceExists(string) (bool, error) { return false, errNotWindows }
func (unsupportedHost) CreateService(ServiceSpec) error    { return errNotWindows }
func (unsupportedHost) StartService(string) error          { return errNotWindows }
func (unsupportedHost) ResolveSID(string) (string, error)  { return "", errNotWindows }
func (unsupportedHost) RootStore(string) keys.RootStore    { return keys.SealedFile{} }
