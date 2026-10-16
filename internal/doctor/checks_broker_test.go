package doctor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/brokerapi"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	klversion "github.com/keylatch/keylatch/internal/version"
)

func fixedProbe(b BrokerState) func(context.Context, llmcontext.Lookup, kexec.CommandRunner) BrokerState {
	return func(context.Context, llmcontext.Lookup, kexec.CommandRunner) BrokerState { return b }
}

func brokerRows(t *testing.T, b BrokerState) map[string]Status {
	t.Helper()
	out := map[string]Status{}
	for _, nc := range brokerChecks(func(string) string { return "" }, nil, fixedProbe(b)) {
		st := nc.fn(context.Background())
		out[st.Name] = st
	}
	return out
}

func TestDoctorBrokerChecks(t *testing.T) {
	// Daemon mode passes, and the other rows say what is left to do.
	rows := brokerRows(t, BrokerState{
		Installed: true, Reachable: true, Version: klversion.Version, Policy: "signed", Presence: "polkit", TPM: true,
	})
	mode := rows["mode.deployment"]
	if !mode.OK || mode.Warn || !strings.Contains(mode.Detail, "daemon mode") || mode.Section != "environment" {
		t.Fatalf("daemon mode row = %+v", mode)
	}
	for _, name := range []string{"broker.version", "broker.tpm", "broker.leftovers", "broker.adopted"} {
		if r := rows[name]; !r.OK || r.Warn || r.Skipped || r.Section != "daemon" {
			t.Errorf("%s row = %+v", name, r)
		}
	}

	// The daemon socket exists but nothing answers: a failure with the command to run.
	rows = brokerRows(t, BrokerState{Installed: true, Error: "connection refused"})
	if mode := rows["mode.deployment"]; mode.OK || !strings.Contains(mode.Fix, "systemctl start keylatchd.socket") {
		t.Fatalf("unreachable daemon row = %+v", mode)
	}

	// Problems with a reachable daemon are warnings that name the fix.
	rows = brokerRows(t, BrokerState{
		Installed: true, Reachable: true, Version: "0.0.1-other", Policy: "signed", Presence: "none",
		Leftovers: []string{"audit-salt", "identity"}, Adopted: []string{"github/token", "stripe/key"},
	})
	for name, want := range map[string]string{
		"broker.version":   "versions differ",
		"broker.tpm":       "no TPM binding",
		"broker.leftovers": "audit-salt, identity",
		"broker.adopted":   "rotate recommended",
	} {
		r := rows[name]
		if !r.OK || !r.Warn || !strings.Contains(r.Detail, want) || r.Fix == "" {
			t.Errorf("%s row = %+v, want a warning mentioning %q", name, r, want)
		}
	}
	if !strings.Contains(rows["broker.adopted"].Detail, "github/token, stripe/key") {
		t.Fatalf("the adopted row must list every upstream key: %q", rows["broker.adopted"].Detail)
	}
}

func TestDoctorInUserWarnWhenBrokerAvailable(t *testing.T) {
	rows := brokerRows(t, BrokerState{})
	mode := rows["mode.deployment"]
	if !mode.OK || !strings.Contains(mode.Detail, "in-user mode") {
		t.Fatalf("in-user row = %+v", mode)
	}
	if runtime.GOOS == "linux" {
		if !mode.Warn || !strings.Contains(mode.Fix, "broker install") {
			t.Fatalf("in-user mode on Linux must warn and name the install command: %+v", mode)
		}
	} else if mode.Warn {
		t.Fatalf("a platform without the broker must not warn: %+v", mode)
	}
	// Without a broker the daemon rows have nothing to say.
	for _, name := range []string{"broker.version", "broker.tpm", "broker.leftovers"} {
		if !rows[name].Skipped {
			t.Errorf("%s must be skipped without a broker: %+v", name, rows[name])
		}
	}
	if !brokerAvailable() && runtime.GOOS == "linux" {
		t.Fatal("the broker is available on Linux")
	}
}

type tpmRunner struct {
	code int
	err  error
	args []string
}

func (r *tpmRunner) Run(_ context.Context, name string, args []string, _ []byte) ([]byte, []byte, int, error) {
	r.args = append([]string{name}, args...)
	return nil, nil, r.code, r.err
}

func (r *tpmRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}

func TestProbeBrokerWithoutASocket(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		switch k {
		case "KEYLATCH_BROKER_SOCKET":
			return filepath.Join(dir, "absent.sock")
		case "KEYLATCH_CONFIG_DIR":
			return dir
		}
		return ""
	}
	if err := os.WriteFile(filepath.Join(dir, "audit-salt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := brokerapi.WriteAdopted(filepath.Join(dir, "broker-adopted.json"), brokerapi.Adopted{UpstreamKey: []string{"a/b"}}); err != nil {
		t.Fatal(err)
	}
	st := probeBroker(context.Background(), env, nil)
	if st.Installed || st.Reachable || len(st.Leftovers) != 1 || st.Leftovers[0] != "audit-salt" || len(st.Adopted) != 1 {
		t.Fatalf("state = %+v", st)
	}

	// A regular file where the socket should be is not a broker.
	if err := os.WriteFile(filepath.Join(dir, "absent.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if st := probeBroker(context.Background(), env, nil); st.Installed {
		t.Fatalf("a regular file is not a socket: %+v", st)
	}
}

func TestProbeBrokerTalksToTheDaemon(t *testing.T) {
	dir, err := os.MkdirTemp("", "kl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "b.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("binding Unix sockets is not permitted here: %v", err)
	}
	defer func() { _ = ln.Close() }()
	// Closing a listener unlinks its socket; keep the file so the last case sees
	// a stale socket nobody listens on, as after a daemon crash.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	reply := brokerapi.Response{OK: true, Status: &brokerapi.Status{Version: "9.9.9", Policy: "signed", Presence: "polkit"}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			line, _ := bufio.NewReader(c).ReadBytes('\n')
			if strings.Contains(string(line), "broker.status") {
				b, _ := json.Marshal(reply)
				_, _ = c.Write(append(b, '\n'))
			}
			_ = c.Close()
		}
	}()
	env := func(k string) string {
		if k == "KEYLATCH_BROKER_SOCKET" {
			return sock
		}
		return ""
	}

	runner := &tpmRunner{}
	st := probeBroker(context.Background(), env, runner)
	if !st.Installed || !st.Reachable || st.Version != "9.9.9" || st.Policy != "signed" || !st.TPM {
		t.Fatalf("state = %+v", st)
	}
	if len(runner.args) < 2 || runner.args[1] != "has-tpm2" {
		t.Fatalf("TPM probe ran %v", runner.args)
	}
	if st := probeBroker(context.Background(), env, &tpmRunner{code: 1}); st.TPM {
		t.Fatal("a failing has-tpm2 means no TPM binding")
	}
	if st := probeBroker(context.Background(), env, &tpmRunner{err: errors.New("no systemd-creds")}); st.TPM {
		t.Fatal("a missing systemd-creds means no TPM binding")
	}

	reply = brokerapi.Response{Code: "refused"}
	if st := probeBroker(context.Background(), env, nil); !st.Installed || st.Reachable || st.Error == "" {
		t.Fatalf("a daemon that refuses status = %+v", st)
	}
	_ = ln.Close()
	if st := probeBroker(context.Background(), env, nil); st.Reachable || st.Error == "" {
		t.Fatalf("a dead socket = %+v", st)
	}
}
