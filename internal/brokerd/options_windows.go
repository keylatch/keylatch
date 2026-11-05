package brokerd

import (
	"os"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/control"
)

func (o *Options) applyPlatform() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	host := NewWindowsHost()
	err = o.applyWindows(host.RootStore(AdminDir(o.StateRoot)), filepath.Dir(self), func(a *AccountMap) func(control.Conn) (*Identity, error) {
		return WindowsIdentifier{Sys: windowsSystem{}, Accounts: a}.Identify
	})
	if err != nil {
		return err
	}
	if o.Listen == nil {
		o.Listen = func() (Listener, error) { return listenPipe(o.Socket) }
	}
	return nil
}
