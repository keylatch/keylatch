package brokerd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/keylatch/keylatch/internal/control"
)

// macPresenceIdentifier is the signing identifier of the presence helper.
const macPresenceIdentifier = "dev.keylatch.presence"

// applyMac fills in what the macOS broker needs and the caller left unset: the
// device root from the System keychain, signed presence through the Secure
// Enclave helper, and the rule that only the signed helper binary may register
// as a helper. self is the path of the running daemon binary.
func (o *Options) applyMac(self string, code CodeResolver) {
	if o.Root == nil {
		store := defaultRootStore(o.StateRoot, self, nil)
		o.Root = store.Load
	}
	if o.Helpers == nil {
		o.Helpers = NewHelperHub()
	}
	if o.Presence == nil {
		o.Presence = &SignedPresence{
			Platform: "secure-enclave",
			Keys:     DirKeys{Dir: filepath.Join(o.StateRoot, "presence")},
			Link:     o.Helpers,
		}
	}
	if o.HelperAdmit == nil {
		o.HelperAdmit = macHelperAdmit(self, code)
	}
}

// macHelperAdmit admits a presence helper only when it is the helper binary
// from the root-owned install directory and its signature carries the same
// team as the daemon's. A build without a team (development) checks the path
// alone.
func macHelperAdmit(self string, code CodeResolver) func(context.Context, control.Peer) error {
	libexec := filepath.Dir(self) + "/"
	return func(ctx context.Context, p control.Peer) error {
		if !strings.HasPrefix(p.Exe, libexec) || filepath.Base(p.Exe) != "keylatch-presence" {
			return fmt.Errorf("brokerd: %q is not the presence helper", p.Exe)
		}
		if code == nil {
			return nil
		}
		own, err := code.Identity(ctx, 0, self)
		if err != nil {
			return nil //nolint:nilerr // an unsigned daemon is a development build; the path check above stands
		}
		team, _, _ := strings.Cut(strings.TrimPrefix(own, "team="), ";")
		if team == "" {
			return nil
		}
		if want := "team=" + team + ";id=" + macPresenceIdentifier; p.Code != want {
			return fmt.Errorf("brokerd: the presence helper is signed as %q, not %q", p.Code, want)
		}
		return nil
	}
}
