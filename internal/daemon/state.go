// Package daemon provides the daemon state file used to persist first-launch
// and other daemon lifecycle flags across process restarts, as well as functions
// for checking and spawning the keylatchd UI server as a background process.
package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// State is the on-disk shape of ~/.keylatch/daemon-state.json.
// All fields are boolean lifecycle flags — no secret values are stored here.
type State struct {
	// FirstLaunchDone is set to true after the first successful daemon start
	// to prevent the first-launch notification from firing again.
	FirstLaunchDone bool `json:"first_launch_done"`
}

// LoadState reads the daemon state file at path.
// If the file does not exist it returns an empty (zero-value) State, which
// indicates that first launch has not yet occurred.
func LoadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, nil
		}
		return State{}, fmt.Errorf("read daemon state %q: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		// Corrupted state file — return zero value (triggers re-notification once).
		return State{}, fmt.Errorf("parse daemon state %q: %w", path, err)
	}
	return s, nil
}

// SaveState atomically writes the state to path.
// The file is created with mode 0o600.
func SaveState(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal daemon state: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".daemon-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp daemon state: %w", err)
	}
	tmpName := tmp.Name()

	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod daemon state temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write daemon state temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close daemon state temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename daemon state to %q: %w", path, err)
	}

	success = true
	return nil
}

const defaultPort = "7890"
const defaultAddr = "127.0.0.1:" + defaultPort

// IsRunning returns true if keylatchd responds to GET /health on defaultAddr.
func IsRunning() bool {
	return PingKeylatchd(defaultAddr)
}

var pingClient = &http.Client{
	Transport: &http.Transport{},
	Timeout:   600 * time.Millisecond,
}

// PingKeylatchd checks if keylatchd is alive at addr.
// addr must be in host:port form (no scheme).
func PingKeylatchd(addr string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/health", nil)
	if err != nil {
		return false
	}
	resp, err := pingClient.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Spawn starts the keylatch UI server (keylatchd) as a detached background
// process and waits up to 2s for it to be ready. Returns an error if the
// process fails to start or does not respond within the timeout.
//
// The daemon is started via `keylatch ui --port 7890 --no-open` so that users
// do not need a separate keylatchd binary on their PATH. cmd.Start is used so
// the child process runs independently without blocking the caller.
func Spawn() error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine keylatch path: %w", err)
	}
	cmd := exec.Command(self, "ui", "--port", defaultPort, "--no-open")
	// Detach: no stdin, stdout, or stderr inherited — silent background.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	detachCommand(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start keylatchd: %w", err)
	}
	// Wait up to 2s for /health to respond.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if PingKeylatchd(defaultAddr) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return fmt.Errorf("keylatchd did not start in time — run 'keylatch doctor' for details")
}
