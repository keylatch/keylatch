//go:build harness

package harness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/paths"
)

var binaries struct{ keylatch, fakeagent string }

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "keylatch-harness-bin")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	binaries.keylatch = filepath.Join(dir, "keylatch"+exe)
	binaries.fakeagent = filepath.Join(dir, "fakeagent"+exe)
	for out, pkg := range map[string]string{
		binaries.keylatch:  "../../cmd/keylatch",
		binaries.fakeagent: "./fakeagent",
	} {
		// keylatch_e2e lets the binary read operator settings from the scratch
		// home instead of the account's real home.
		cmd := exec.Command("go", "build", "-tags", "harness keylatch_e2e", "-o", out, pkg)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if b, err := cmd.CombinedOutput(); err != nil {
			panic("go build " + pkg + ": " + err.Error() + "\n" + string(b))
		}
	}
	os.Exit(m.Run())
}

// canary values planted in a world. A scenario leaks when one of them reaches
// the agent.
const (
	canarySecret  = "sk-harness-canary-4b1f0c0de5a17e9d"
	canarySession = "harness-bw-session-canary-77c3a91e"
)

// world is a throwaway user home with a bootstrapped file vault, one stored
// credential and the guard installed for the agent under test.
type world struct {
	t      *testing.T
	home   string
	config string
	// identity is the raw key-encryption key the bootstrap wrote.
	identity []byte
}

func newWorld(t *testing.T, profile string) *world {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("the installed guard is a bash script")
	}
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil && runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	w := &world{t: t, home: home, config: filepath.Join(home, ".keylatch")}

	// The operator's own config is the one way to a plaintext vault key on a
	// host with no keyring or terminal.
	if runtime.GOOS != "windows" {
		c := config.Default()
		c.AllowInsecureFileKEK = true
		if err := config.Save(paths.DefaultConfig(w.operatorHome()), c); err != nil {
			t.Fatal(err)
		}
	}
	w.must("bootstrap", "--backend", "file")
	w.mustStdin(canarySecret+"\n", "connect", "openai", "--non-interactive", "--no-test", "--stdin-field", "api_key")
	w.must("install-guard", profile)
	identity, err := os.ReadFile(filepath.Join(w.config, "keyring", "identity"))
	if err != nil {
		t.Fatal(err)
	}
	w.identity = identity
	return w
}

// operatorHome is a directory of its own, so a config planted under the home
// the agent sees is never mistaken for the operator's.
func (w *world) operatorHome() string { return filepath.Join(w.home, "operator-home") }

// humanEnv is the environment of a person at a plain terminal.
func (w *world) humanEnv() []string {
	var env []string
	for _, e := range os.Environ() {
		name, _, _ := strings.Cut(e, "=")
		if strings.HasPrefix(name, "KEYLATCH_") || name == "HOME" || strings.HasPrefix(name, "CLAUDE") || strings.HasPrefix(name, "CODEX") ||
			name == "XDG_CONFIG_HOME" || name == "XDG_RUNTIME_DIR" || name == "DBUS_SESSION_BUS_ADDRESS" {
			continue
		}
		env = append(env, e)
	}
	env = append(env, noKeyringEnv()...)
	return append(env,
		"HOME="+w.home,
		"USERPROFILE="+w.home,
		"KEYLATCH_CONFIG_DIR="+w.config,
		"KEYLATCH_E2E_OPERATOR_HOME="+w.operatorHome(),
		"KEYLATCH_API_KEY="+canarySecret,
		"KEYLATCH_BACKEND=file",
	)
}

// noKeyringEnv keeps the binary away from the login keychain of a CI runner,
// where an unlock prompt can never be answered.
func noKeyringEnv() []string {
	if runtime.GOOS == "darwin" {
		return []string{"KEYLATCH_E2E_NO_OS_KEYRING=1"}
	}
	return nil
}

// commandTimeout bounds every process a scenario starts, so a prompt nobody
// can answer fails the row instead of hanging the run.
const commandTimeout = 3 * time.Minute

func boundedCommand(name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = 10 * time.Second
	return cmd, cancel
}

func (w *world) human(args ...string) (string, string, int) { return w.humanStdin("", args...) }

func (w *world) humanStdin(stdin string, args ...string) (string, string, int) {
	w.t.Helper()
	cmd, cancel := boundedCommand(binaries.keylatch, args...)
	defer cancel()
	cmd.Env = w.humanEnv()
	cmd.Dir = w.home
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	code := exitCode(cmd.Run())
	return out.String(), errb.String(), code
}

// write creates a file below the home directory.
func (w *world) write(rel, content string, mode os.FileMode) {
	w.t.Helper()
	path := filepath.Join(w.home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		w.t.Fatal(err)
	}
}

// installVendorCLIs puts stand-ins for the password-manager and cloud CLIs on
// the agent's PATH. Each prints a canary the way the real tool would print a
// secret once its own session is unlocked.
func (w *world) installVendorCLIs() {
	w.t.Helper()
	w.write("bin/bw", "#!/bin/bash\n[ -n \"$BW_SESSION\" ] && echo \"$BW_SESSION\"\n", 0o700)
	w.write("bin/op", "#!/bin/bash\necho "+vendorCanary+"\n", 0o700)
	w.write("bin/vault", "#!/bin/bash\necho "+vendorCanary+"\n", 0o700)
	w.write("bin/aws", "#!/bin/bash\necho "+vendorCanary+"\n", 0o700)
}

func (w *world) must(args ...string) { w.mustStdin("", args...) }

func (w *world) mustStdin(stdin string, args ...string) {
	w.t.Helper()
	out, errb, code := w.humanStdin(stdin, args...)
	if code != 0 {
		w.t.Fatalf("keylatch %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errb)
	}
}

func exitCode(err error) int {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ee):
		return ee.ExitCode()
	default:
		return -1
	}
}

// outcome is what the fake agent reports for one tool call.
type outcome struct {
	Blocked  bool   `json:"blocked"`
	Reason   string `json:"reason"`
	ExitCode int    `json:"exit_code"`
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
}

func (o outcome) text() string { return string(o.Stdout) + "\n" + string(o.Stderr) }

// agent runs one tool call as the fake agent would.
func (w *world) agent(profile, tool string, input map[string]string, extraEnv ...string) outcome {
	w.t.Helper()
	in, err := json.Marshal(input)
	if err != nil {
		w.t.Fatal(err)
	}
	// The agent finds keylatch on PATH, as it does after an install; stand-in
	// vendor CLIs in <home>/bin come first.
	path := strings.Join([]string{filepath.Join(w.home, "bin"), filepath.Dir(binaries.keylatch), os.Getenv("PATH")}, string(os.PathListSeparator))
	env := append([]string{"KEYLATCH_CONFIG_DIR=" + w.config, "PATH=" + path}, noKeyringEnv()...)
	env = append(env, extraEnv...)
	cmd, cancel := boundedCommand(binaries.fakeagent,
		"--profile", profile, "--home", w.home, "--tool", tool, "--input", string(in),
		"--env", strings.Join(env, "\n"))
	defer cancel()
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		w.t.Fatalf("fakeagent: %v\n%s", err, errb.String())
	}
	var o outcome
	if err := json.Unmarshal(out.Bytes(), &o); err != nil {
		w.t.Fatalf("fakeagent output %q: %v", out.String(), err)
	}
	return o
}
