package control

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRemoteFlagOnlyBeforeTheDashes(t *testing.T) {
	for args, want := range map[string]bool{
		"--remote host:1 openai list":   true,
		"openai list --remote=host:1":   true,
		"openai list -- --remote x":     false,
		"openai list --remote-x y":      false,
		"openai list --remoted":         false,
		"openai list":                   false,
		"openai --json -- cmd --remote": false,
	} {
		if got := remoteFlag(strings.Fields(args)); got != want {
			t.Errorf("%q = %v, want %v", args, got, want)
		}
	}
}

// A call that names a remote broker runs in the CLI, whatever daemon exists.
func TestRemoteCallIsNotServedByTheLocalDaemon(t *testing.T) {
	lookup := func(k string) string {
		if k == "KEYLATCH_SOCKET" {
			return "/nonexistent/keylatch.sock"
		}
		return ""
	}
	var out, errOut bytes.Buffer
	code, handled := Handle(context.Background(), lookup, []string{"call", "--remote", "10.0.0.5:7443", "c", "a"}, IO{Out: &out, ErrOut: &errOut})
	if handled || code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("call --remote: handled=%v code=%d out=%q err=%q", handled, code, out.String(), errOut.String())
	}
}
