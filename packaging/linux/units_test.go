package linuxpkg

import (
	"strings"
	"testing"
)

// directives parses a unit file into section -> key -> values.
func directives(t *testing.T, name string) map[string]map[string][]string {
	t.Helper()
	b, err := Files.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string][]string{}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			section = strings.Trim(line, "[]")
			out[section] = map[string][]string{}
		default:
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("%s: %q is not a directive", name, line)
			}
			out[section][k] = append(out[section][k], v)
		}
	}
	return out
}

func TestBrokerServiceIsHardened(t *testing.T) {
	svc := directives(t, "systemd/keylatchd.service")["Service"]
	for k, want := range map[string]string{
		"User":                    "keylatch",
		"StateDirectory":          "keylatch",
		"StateDirectoryMode":      "0700",
		"RuntimeDirectory":        "keylatch",
		"ProtectSystem":           "strict",
		"ProtectHome":             "yes",
		"NoNewPrivileges":         "yes",
		"PrivateTmp":              "yes",
		"PrivateDevices":          "yes",
		"MemoryDenyWriteExecute":  "yes",
		"RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
		"SystemCallFilter":        "@system-service",
		"LoadCredentialEncrypted": "keylatch-root:/etc/keylatch/root.cred",
		"CapabilityBoundingSet":   "",
		"LockPersonality":         "yes",
		"RestrictNamespaces":      "yes",
		"RestrictSUIDSGID":        "yes",
		"ProtectKernelTunables":   "yes",
		"ProtectKernelModules":    "yes",
		"ProtectControlGroups":    "yes",
		"SystemCallArchitectures": "native",
		"UMask":                   "0077",
		"ExecStart":               "/usr/bin/keylatchd broker",
	} {
		if got := svc[k]; len(got) != 1 || got[0] != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// The daemon identifies peers through /proc, so other users' processes must stay visible.
	if got := svc["ProtectProc"]; len(got) != 0 {
		t.Errorf("ProtectProc = %q: hiding processes would blind the daemon's peer identification", got)
	}
}

func TestBrokerSocketIsWorldConnectableAndActivated(t *testing.T) {
	d := directives(t, "systemd/keylatchd.socket")
	sock := d["Socket"]
	if got := sock["ListenStream"]; len(got) != 1 || got[0] != "/run/keylatch/broker.sock" {
		t.Errorf("ListenStream = %q", got)
	}
	if got := sock["SocketMode"]; len(got) != 1 || got[0] != "0666" {
		t.Errorf("SocketMode = %q: the daemon authenticates peers itself, so any user may connect", got)
	}
	svc := directives(t, "systemd/keylatchd.service")
	if got := svc["Unit"]["Requires"]; len(got) != 1 || got[0] != "keylatchd.socket" {
		t.Errorf("the service must require its socket: %q", got)
	}
}

func TestSysusersAndPolkitFiles(t *testing.T) {
	b, err := Files.ReadFile("sysusers.d/keylatch.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "u keylatch ") || !strings.Contains(string(b), "/usr/sbin/nologin") {
		t.Errorf("sysusers entry:\n%s", b)
	}
	p, err := Files.ReadFile("polkit/dev.keylatch.policy")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(p), `id="dev.keylatch.privileged"`) || !strings.Contains(string(p), "auth_self") || strings.Contains(string(p), "auth_self_keep") || strings.Contains(string(p), "auth_admin_keep") {
		t.Errorf("polkit policy must ask for the user's own password and never retain it:\n%s", p)
	}
}
