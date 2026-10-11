package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cbFakeBrowser puts an "open"/"xdg-open" stub first on PATH that records the
// URL it was asked to open.
func cbFakeBrowser(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script browser stub is POSIX-only")
	}
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "opened")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s' \"$1\" > %q\n", marker)
	for _, name := range []string{"open", "xdg-open"} {
		require.NoError(t, os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o700))
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return marker
}

func TestUI_InvalidScope(t *testing.T) {
	cbIsolate(t)
	_, _, err := cbRun(t, "ui", "--scope", "root")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ui: --scope")
}

func TestUI_PrintsBootstrapURLAndFailsOnBusyPort(t *testing.T) {
	cbIsolate(t)
	port := cbBusyPort(t)

	out, _, err := cbRun(t, "ui", "--no-open", "--demo", "--port", strconv.Itoa(port))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen on")
	assert.Contains(t, out, "open this URL in your browser")
	assert.Contains(t, out, fmt.Sprintf("http://127.0.0.1:%d/", port))
	assert.Contains(t, out, "demo mode")
	assert.Contains(t, out, fmt.Sprintf("listening on 127.0.0.1:%d", port))
	assert.NotContains(t, out, "LLM session")
}

func TestUI_LLMSessionLocksScopeAndBind(t *testing.T) {
	cbIsolate(t)
	t.Setenv("CLAUDECODE", "1")
	t.Setenv("KEYLATCH_UI_LISTEN", "0.0.0.0:9")
	port := cbBusyPort(t)

	out, stderr, err := cbRun(t, "ui", "--no-open", "--scope", "admin", "--unsafe-bind-all",
		"--listen", "0.0.0.0:1", "--port", strconv.Itoa(port))
	require.Error(t, err)
	assert.Contains(t, stderr, "scope locked to status-only")
	assert.Contains(t, stderr, "--unsafe-bind-all ignored")
	assert.Contains(t, stderr, "--listen/KEYLATCH_UI_LISTEN ignored")
	assert.Contains(t, out, "scope=status-only (LLM session)")
	assert.Contains(t, out, fmt.Sprintf("listening on 127.0.0.1:%d", port))
}

func TestUI_OpensBrowserWithBootstrapURL(t *testing.T) {
	cbIsolate(t)
	marker := cbFakeBrowser(t)
	port := cbBusyPort(t)

	out, _, err := cbRun(t, "ui", "--port", strconv.Itoa(port))
	require.Error(t, err)
	require.True(t, cbWaitFor(t, 5*time.Second, func() bool {
		data, readErr := os.ReadFile(marker)
		return readErr == nil && len(data) > 0
	}), "browser stub was not invoked")
	opened, err := os.ReadFile(marker)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(opened), fmt.Sprintf("http://127.0.0.1:%d/", port)))
	assert.Contains(t, out, string(opened))
}

func TestOpenBrowser_NoLauncherAvailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	assert.NoError(t, openBrowser("http://127.0.0.1:1/"), "openBrowser is best-effort and never fails")
}
