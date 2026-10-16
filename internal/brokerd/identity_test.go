package brokerd

import (
	"errors"
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
