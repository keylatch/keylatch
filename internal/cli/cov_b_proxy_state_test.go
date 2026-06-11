package cli

// cov_b_proxy_state_test.go — Agent B coverage for proxy_cmd.go helper functions.
// Tests for writeProxyState, readProxyState, removeProxyState, proxyPIDPathFromDir,
// proxyStatePathFromDir.
// Hermetic: no network, no OS keychain.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCovB_ProxyStatePathFromDir(t *testing.T) {
	path := proxyStatePathFromDir("/tmp/test")
	if path != "/tmp/test/proxy.state" {
		t.Errorf("unexpected path: %s", path)
	}
}

func TestCovB_ProxyPIDPathFromDir(t *testing.T) {
	path := proxyPIDPathFromDir("/tmp/test")
	if path != "/tmp/test/proxy.pid" {
		t.Errorf("unexpected path: %s", path)
	}
}

func TestWriteReadProxyState_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "proxy.state")

	st := proxyState{PID: 12345, Port: 9090}
	if err := writeProxyState(statePath, st); err != nil {
		t.Fatalf("writeProxyState: %v", err)
	}

	loaded, err := readProxyState(statePath)
	if err != nil {
		t.Fatalf("readProxyState: %v", err)
	}

	if loaded.PID != 12345 {
		t.Errorf("expected PID=12345, got: %d", loaded.PID)
	}
	if loaded.Port != 9090 {
		t.Errorf("expected Port=9090, got: %d", loaded.Port)
	}
}

func TestReadProxyState_NotFound(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "proxy.state")

	st, err := readProxyState(statePath)
	if err != nil {
		t.Fatalf("expected nil error for missing state file, got: %v", err)
	}
	if st.PID != 0 || st.Port != 0 {
		t.Errorf("expected zero-value state for missing file, got: %+v", st)
	}
}

func TestReadProxyState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "proxy.state")

	if err := os.WriteFile(statePath, []byte("{bad json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := readProxyState(statePath)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestRemoveProxyState_Exists(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "proxy.state")

	if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := removeProxyState(statePath); err != nil {
		t.Fatalf("removeProxyState: %v", err)
	}

	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Error("expected file to be removed")
	}
}

func TestRemoveProxyState_NotFound(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "nonexistent.state")

	// Should not return an error for missing file.
	if err := removeProxyState(statePath); err != nil {
		t.Fatalf("removeProxyState for non-existent file should not error, got: %v", err)
	}
}

func TestWriteProxyState_AtomicNoTmpLeft(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "proxy.state")

	if err := writeProxyState(statePath, proxyState{PID: 1, Port: 8080}); err != nil {
		t.Fatalf("writeProxyState: %v", err)
	}

	// No .tmp file should remain.
	if _, err := os.Stat(statePath + ".tmp"); !os.IsNotExist(err) {
		t.Error("expected .tmp file to be cleaned up after atomic write")
	}
}
