package brokerd

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/brokerd/keys"
	"github.com/keylatch/keylatch/internal/control"
)

// applyWindows fills in what the Windows service needs and the caller left
// unset: the device root from the CNG-sealed file, the account map, signed
// presence through the Windows Hello helper, and the rule that only the helper
// installed beside the daemon may register as a helper. identify is the
// platform's peer lookup; installDir is where the Keylatch binaries live.
func (o *Options) applyWindows(root keys.RootStore, installDir string, identify func(*AccountMap) func(control.Conn) (*Identity, error)) error {
	accounts, err := OpenAccounts(filepath.Join(o.StateRoot, "accounts.json"))
	if err != nil {
		return err
	}
	if o.Root == nil {
		o.Root = root.Load
	}
	if o.Identify == nil && identify != nil {
		o.Identify = identify(accounts)
	}
	if o.Helpers == nil {
		o.Helpers = NewHelperHub()
	}
	if o.Presence == nil {
		o.Presence = &SignedPresence{
			Platform: "windows-hello",
			Keys:     DirKeys{Dir: filepath.Join(AdminDir(o.StateRoot), "presence"), NameOf: accounts.SID},
			Link:     o.Helpers,
		}
	}
	if o.HelperAdmit == nil {
		o.HelperAdmit = winHelperAdmit(installDir)
	}
	return nil
}

// winHelperAdmit admits a presence helper only when it is the helper binary
// from the administrator-owned install directory.
func winHelperAdmit(installDir string) func(context.Context, control.Peer) error {
	norm := func(s string) string { return strings.ToLower(path.Clean(strings.ReplaceAll(s, `\`, "/"))) }
	dir := norm(installDir) + "/"
	return func(_ context.Context, p control.Peer) error {
		exe := norm(p.Exe)
		if !strings.HasPrefix(exe, dir) || path.Base(exe) != "keylatch-presence.exe" {
			return fmt.Errorf("brokerd: %q is not the presence helper", p.Exe)
		}
		return nil
	}
}
