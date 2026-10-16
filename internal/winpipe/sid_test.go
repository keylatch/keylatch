package winpipe

import (
	"errors"
	"testing"
)

func TestServiceSIDMatchesWindows(t *testing.T) {
	// The SID Windows documents for the TrustedInstaller service.
	if got, want := ServiceSID("TrustedInstaller"), "S"+"-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; got != want {
		t.Fatalf("ServiceSID = %s, want %s", got, want)
	}
	if ServiceSID("keylatch") != ServiceSID("KEYLATCH") {
		t.Fatal("service names are case-insensitive")
	}
}

func TestStubsOffWindows(t *testing.T) {
	if _, err := Listen("x", ""); err == nil {
		t.Skip("running on Windows")
	}
	if _, err := Dial("x", 0); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Dial = %v", err)
	}
	var c Conn
	if _, _, err := c.ClientProcess(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ClientProcess = %v", err)
	}
	if _, err := c.ServerProcess(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ServerProcess = %v", err)
	}
	if err := c.CloseWrite(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("CloseWrite = %v", err)
	}
	var l Listener
	if _, err := l.Accept(); !errors.Is(err, ErrUnsupported) || l.Close() != nil || Exists("x") {
		t.Fatal("listener stubs misbehave")
	}
}
