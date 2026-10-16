package control

import (
	"errors"
	"runtime"
	"testing"
)

func TestPipePaths(t *testing.T) {
	if !isPipePath(`\\.\pipe\keylatch-broker`) || isPipePath("/run/keylatch/broker.sock") || isPipePath(`C:\pipe`) {
		t.Fatal("isPipePath misclassifies a path")
	}
	if brokerServiceSID == "" || brokerServiceSID[:9] != "S"+"-1-5-80-" {
		t.Fatalf("service SID = %q", brokerServiceSID)
	}
}

func TestDialPipeWithoutAServer(t *testing.T) {
	c := &Client{socket: `\\.\pipe\keylatch-no-such-pipe`, broker: true}
	if _, err := c.dial(); !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("dial = %v", err)
	}
	if isSocket(`\\.\pipe\keylatch-no-such-pipe`) {
		t.Fatal("a pipe that does not exist was reported as a socket")
	}
	if runtime.GOOS != "windows" {
		if _, err := processSID(1); err == nil {
			t.Fatal("process SIDs are only available on Windows")
		}
	}
}
