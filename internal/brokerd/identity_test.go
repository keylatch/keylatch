package brokerd

import (
	"errors"
	"strings"
	"testing"
)

func TestParseStartTime(t *testing.T) {
	// comm holds spaces and parentheses; field 22 follows the last ')'.
	stat := "1234 (a (weird) name) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100 18446744073709551615"
	got, err := ParseStartTime(stat)
	if err != nil || got != "987654" {
		t.Fatalf("ParseStartTime = %q, %v", got, err)
	}
	for _, bad := range []string{"", "no parenthesis", "1 (x) S 1 2"} {
		if _, err := ParseStartTime(bad); err == nil {
			t.Fatalf("ParseStartTime(%q) must fail", bad)
		}
	}
}

func TestCgroupResolved(t *testing.T) {
	for name, tc := range map[string]struct{ dump, want string }{
		"unified":                {"0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n", "/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope"},
		"hybrid prefers unified": {"12:cpu:/legacy\n1:name=systemd:/named\n0::/unified\n", "/unified"},
		"v1 systemd":             {"12:cpu:/legacy\n1:name=systemd:/system.slice/keylatchd.service\n", "/system.slice/keylatchd.service"},
		"none":                   {"12:cpu:/legacy\n", ""},
		"garbage":                {"not a cgroup dump", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := ParseCgroup(tc.dump); got != tc.want {
				t.Fatalf("ParseCgroup = %q, want %q", got, tc.want)
			}
		})
	}
}

// FuzzPeerIdentity feeds arbitrary /proc text to the parsers the daemon trusts
// to identify a peer, and arbitrary control group paths to the agent-scope
// check. Nothing may panic, and a start time or cgroup must come from the text.
func FuzzPeerIdentity(f *testing.F) {
	f.Add("4242 (agent) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 555 1000 100 1", "0::/user.slice/user-1000.slice/app.slice/term.scope\n")
	f.Add("1 ((((", "::\n::")
	f.Add("", "")
	f.Add("1 (x) "+string(make([]byte, 64)), "1:name=systemd:/\n0::/a/b/c")

	sessions := NewSessions([]byte("0123456789abcdef0123456789abcdef"), nil)
	if _, err := sessions.Register(1000, "agent-fuzz1234", "/user.slice/user-1000.slice/keylatch-agent-agent-fuzz1234.scope"); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, stat, cgroup string) {
		if start, err := ParseStartTime(stat); err == nil && start == "" && len(stat) > 0 && !strings.ContainsAny(stat, ")") {
			t.Fatalf("a start time was invented from %q", stat)
		}
		cg := ParseCgroup(cgroup)
		if cg != "" && !strings.Contains(cgroup, cg) {
			t.Fatalf("ParseCgroup returned %q, which is not in its input", cg)
		}
		// Only paths inside the registered scope are agents; anything else never is.
		inside := sessions.InAgentScope(cg)
		if inside && !strings.HasPrefix(cg, "/user.slice/user-1000.slice/keylatch-agent-agent-fuzz1234.scope") {
			t.Fatalf("%q classified as inside a scope it does not belong to", cg)
		}
	})
}

func TestIdentityWithoutPinIsUnsupported(t *testing.T) {
	var id *Identity
	if err := id.Verify(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Verify on nil = %v", err)
	}
	id.Close()
	if err := (&Identity{}).Verify(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Verify without a pin = %v", err)
	}
}
