package brokerd

import (
	"context"
	"testing"

	"github.com/keylatch/keylatch/internal/control"
)

func TestApplyMacFillsInWhatIsUnset(t *testing.T) {
	var o Options
	o.StateRoot = t.TempDir()
	o.applyMac("/usr/local/libexec/keylatch/keylatchd", nil)
	if o.Root == nil || o.Helpers == nil || o.HelperAdmit == nil {
		t.Fatalf("options = %+v", o)
	}
	sp, ok := o.Presence.(*SignedPresence)
	if !ok || sp.Name() != "secure-enclave" || sp.Link != o.Helpers {
		t.Fatalf("presence = %#v", o.Presence)
	}

	keep := &fakePresenceMethod{}
	o2 := Options{StateRoot: t.TempDir(), Presence: keep, Helpers: NewHelperHub()}
	o2.applyMac("/x/keylatchd", nil)
	if o2.Presence != PresenceMethod(keep) {
		t.Fatal("a presence method the caller chose was replaced")
	}
}

type fakePresenceMethod struct{}

func (*fakePresenceMethod) Name() string { return "fake" }
func (*fakePresenceMethod) Verify(context.Context, Subject, string, string) error {
	return nil
}

func TestMacHelperAdmit(t *testing.T) {
	const self = "/usr/local/libexec/keylatch/keylatchd"
	const helper = "/usr/local/libexec/keylatch/Keylatch Presence.app/Contents/MacOS/keylatch-presence"
	admit := macHelperAdmit(self, fixedCode("team=ABCDE12345;id=dev.keylatch.broker"))
	ctx := context.Background()
	if err := admit(ctx, control.Peer{Exe: helper, Code: "team=ABCDE12345;id=dev.keylatch.presence"}); err != nil {
		t.Fatalf("the signed helper = %v", err)
	}
	for name, p := range map[string]control.Peer{
		"other team":        {Exe: helper, Code: "team=ZZZZZZZZZZ;id=dev.keylatch.presence"},
		"other identifier":  {Exe: helper, Code: "team=ABCDE12345;id=dev.keylatch.cli"},
		"unsigned":          {Exe: helper},
		"outside libexec":   {Exe: "/Users/alice/keylatch-presence", Code: "team=ABCDE12345;id=dev.keylatch.presence"},
		"different command": {Exe: "/usr/local/libexec/keylatch/keylatch", Code: "team=ABCDE12345;id=dev.keylatch.presence"},
	} {
		if err := admit(ctx, p); err == nil {
			t.Errorf("%s was admitted", name)
		}
	}

	// A development build of the daemon has no team: the path decides.
	dev := macHelperAdmit(self, fixedCode(""))
	if err := dev(ctx, control.Peer{Exe: helper}); err != nil {
		t.Fatalf("development build = %v", err)
	}
	if err := dev(ctx, control.Peer{Exe: "/tmp/keylatch-presence"}); err == nil {
		t.Fatal("a helper outside the install directory was admitted")
	}
	noTeam := macHelperAdmit(self, fixedCode("team=;id=dev.keylatch.broker"))
	if err := noTeam(ctx, control.Peer{Exe: helper}); err != nil {
		t.Fatalf("ad hoc signed daemon = %v", err)
	}
	if err := macHelperAdmit(self, nil)(ctx, control.Peer{Exe: helper}); err != nil {
		t.Fatalf("no code resolver = %v", err)
	}
}
