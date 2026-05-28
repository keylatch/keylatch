package daemon_test

// state_test.go tests the daemon state load/save lifecycle for §2.6,
// as well as the PingKeylatchd liveness check.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/keylatch/keylatch/internal/daemon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoadState_NotExist returns a zero-value State (first_launch_done=false)
// when the file does not exist.
func TestLoadState_NotExist(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "daemon-state.json")

	s, err := daemon.LoadState(path)
	require.NoError(t, err, "LoadState on missing file should not error")
	assert.False(t, s.FirstLaunchDone, "FirstLaunchDone should be false before first launch")
}

// TestSaveLoad_RoundTrip verifies that a saved state round-trips correctly.
func TestSaveLoad_RoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "daemon-state.json")

	original := daemon.State{FirstLaunchDone: true}
	require.NoError(t, daemon.SaveState(path, original))

	loaded, err := daemon.LoadState(path)
	require.NoError(t, err)
	assert.Equal(t, original, loaded)
}

// TestSaveState_FileMode verifies that the saved state file has mode 0600.
func TestSaveState_FileMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "daemon-state.json")

	require.NoError(t, daemon.SaveState(path, daemon.State{FirstLaunchDone: false}))

	info, err := os.Stat(path)
	require.NoError(t, err)
	// Mode check: 0o600 expected.
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
			"daemon state file should have mode 0600")
	}
}

// TestSaveState_Idempotent verifies that saving twice produces the last value.
func TestSaveState_Idempotent(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "daemon-state.json")

	require.NoError(t, daemon.SaveState(path, daemon.State{FirstLaunchDone: false}))
	require.NoError(t, daemon.SaveState(path, daemon.State{FirstLaunchDone: true}))

	s, err := daemon.LoadState(path)
	require.NoError(t, err)
	assert.True(t, s.FirstLaunchDone)
}

// TestPingKeylatchdReturnsTrue verifies that PingKeylatchd returns true when
// a server responds with HTTP 200 on the /health endpoint.
func TestPingKeylatchdReturnsTrue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Strip the "http://" scheme — PingKeylatchd expects host:port only.
	addr := srv.Listener.Addr().String()
	if !daemon.PingKeylatchd(addr) {
		t.Fatal("expected true when server returns 200")
	}
}

// TestPingKeylatchdReturnsFalse verifies that PingKeylatchd returns false when
// no server is listening on the given address.
func TestPingKeylatchdReturnsFalse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	if daemon.PingKeylatchd(addr) {
		t.Fatal("expected false when no server is listening")
	}
}

// TestPingKeylatchdReturnsFalseOn404 verifies that PingKeylatchd returns false
// when the server responds with a non-200 status.
func TestPingKeylatchdReturnsFalseOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	if daemon.PingKeylatchd(addr) {
		t.Fatal("expected false when server returns 404")
	}
}
