//go:build linux

package ipc

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gdFakeOpener installs a fake xdg-open that records its argv into a file.
func gdFakeOpener(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + out + ".part && mv " + out + ".part " + out + "\n"
	if err := os.WriteFile(filepath.Join(dir, "xdg-open"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":/usr/bin:/bin")
	return out
}

func gdWaitFile(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			return string(b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s never written", path)
	return ""
}

func TestOpenSystemBrowser_LaunchesOnlyValidatedURL(t *testing.T) {
	h := openSystemBrowserHandler()
	for _, u := range []string{"https://keylatch.example/approvals/1?x=y", "keylatch://approvals/abc"} {
		out := gdFakeOpener(t)
		res, err := h(context.Background(), map[string]any{"url": u}, nil)
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if m, ok := res.(map[string]any); !ok || m["ok"] != true {
			t.Errorf("%s: result = %#v", u, res)
		}
		if got := gdWaitFile(t, out); got != u+"\n" {
			t.Errorf("opener argv = %q, want exactly the URL", got)
		}
	}
}

func TestOpenSystemBrowser_RejectedSchemeNeverLaunches(t *testing.T) {
	out := gdFakeOpener(t)
	h := openSystemBrowserHandler()
	for _, u := range []string{"file:///etc/shadow", "HTTP://x", "-https://x", "data:text/html,x"} {
		if _, err := h(context.Background(), map[string]any{"url": u}, nil); err == nil {
			t.Errorf("%q must be rejected", u)
		}
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Error("opener must not run for rejected URLs")
	}
}

func TestOpenSystemBrowser_OpenerMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	h := openSystemBrowserHandler()
	_, err := h(context.Background(), map[string]any{"url": "https://x.example"}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "OpenSystemBrowser: ") {
		t.Fatalf("want wrapped launch error, got %v", err)
	}

	reg := NewMethodRegistry()
	reg.Register(MethodOpenSystemBrowser, h)
	resp := reg.Dispatch(context.Background(), Request{Method: MethodOpenSystemBrowser, Params: map[string]any{"url": "https://x.example"}}, nil)
	if resp.Error != "internal_error" || strings.Contains(resp.Error, "PATH") {
		t.Errorf("launch failure must not leak detail over IPC: %+v", resp)
	}
}
