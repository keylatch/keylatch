//go:build linux

package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// ccPTY makes os.Stdin the follower side of a fresh pseudo-terminal and
// returns the controller, onto which the test types its answers.
func ccPTY(t *testing.T) *os.File {
	t.Helper()
	ctl, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty support: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(ctl.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = ctl.Close()
		t.Skipf("unlockpt: %v", err)
	}
	n, err := unix.IoctlGetInt(int(ctl.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = ctl.Close()
		t.Skipf("ptsname: %v", err)
	}
	follower, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		_ = ctl.Close()
		t.Skipf("open pts: %v", err)
	}
	// Drain echoed output so the line discipline never blocks.
	go func() { _, _ = io.Copy(io.Discard, ctl) }()

	old := os.Stdin
	os.Stdin = follower
	t.Cleanup(func() {
		os.Stdin = old
		_ = follower.Close()
		_ = ctl.Close()
	})
	if !stdinIsTTY() {
		t.Skip("pty follower not detected as a terminal")
	}
	return ctl
}

// ccCaptureStderr redirects os.Stderr (where hidden prompts are written) and
// returns a function yielding everything written so far, once.
func ccCaptureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	var got *string
	collect := func() string {
		if got == nil {
			os.Stderr = old
			_ = w.Close()
			s := <-done
			got = &s
		}
		return *got
	}
	t.Cleanup(func() { collect() })
	return collect
}

// ccHighEntropy builds a 32-character mixed alphabet string at runtime.
func ccHighEntropy() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var b strings.Builder
	for i := 0; i < 32; i++ {
		b.WriteByte(alphabet[(i*7)%len(alphabet)])
	}
	return b.String()
}

func TestCCConnectTTY_PromptsForMissingFields(t *testing.T) {
	cfgDir := ccEnv(t)
	up := ccNewUpstream(t)
	tmpl := strings.Replace(ccTemplate("cctty", up.srv.URL),
		"auth_flow: api_key\n",
		"  - name: org_id\n    required: false\n    sensitive: false\n  - name: project\n    label: Project\n    required: false\n    sensitive: false\nauth_flow: api_key\n", 1)
	ccWriteTemplate(t, cfgDir, "cctty", tmpl)
	ctl := ccPTY(t)
	prompts := ccCaptureStderr(t)

	secret := ccSecret("tty")
	org := ccHighEntropy()
	if _, err := ctl.WriteString(secret + "\n" + org + "\n\n"); err != nil {
		t.Fatalf("type answers: %v", err)
	}

	out, errOut, err := ccRun(t, "", "connect", "cctty")
	shown := prompts()
	if err != nil {
		t.Fatalf("connect: %v (%s)", err, errOut)
	}
	if !strings.Contains(out, "v cctty — connection verified") {
		t.Fatalf("stdout = %q", out)
	}
	for _, p := range []string{"Enter API Key for cctty", "Enter org_id for cctty", "Enter Project for cctty"} {
		if !strings.Contains(shown, p) {
			t.Errorf("prompt %q not shown; stderr: %q", p, shown)
		}
	}
	if !strings.Contains(errOut, `warning: field "org_id" looks like a high-entropy secret`) {
		t.Errorf("high-entropy warning missing for non-sensitive field: %q", errOut)
	}
	if strings.Contains(errOut, `field "project"`) {
		t.Errorf("empty optional answer must not warn: %q", errOut)
	}
	ccAssertNoLeak(t, secret, out, errOut, shown)
	ccAssertNoLeak(t, org, out, errOut, shown)

	if auths, _ := up.seen(); len(auths) != 1 || auths[0] != "Bearer "+secret {
		t.Fatalf("typed secret not used upstream: %q", auths)
	}
	if got, err := ccVaultGet(t, "default/ai/cctty/api_key"); err != nil || got != secret {
		t.Fatalf("stored api_key = %q, %v", got, err)
	}
	if got, err := ccVaultGet(t, "default/ai/cctty/org_id"); err != nil || got != org {
		t.Fatalf("stored org_id = %q, %v", got, err)
	}
	if _, err := ccVaultGet(t, "default/ai/cctty/project"); err == nil {
		t.Fatal("empty optional answer must not be stored")
	}
}

func TestCCConnectTTY_FieldAtPrompt(t *testing.T) {
	ccProvider(t, "ccask")
	ctl := ccPTY(t)
	prompts := ccCaptureStderr(t)
	secret := ccSecret("ask")
	if _, err := ctl.WriteString(secret + "\n"); err != nil {
		t.Fatal(err)
	}

	out, errOut, err := ccRun(t, "", "connect", "ccask", "-f", "api_key=@prompt", "--no-test", "--non-interactive")
	shown := prompts()
	if err != nil {
		t.Fatalf("connect: %v (%s)", err, errOut)
	}
	if !strings.Contains(shown, "Enter api_key") {
		t.Fatalf("prompt not shown: %q", shown)
	}
	if !strings.Contains(out, "stored (connection test skipped)") {
		t.Fatalf("stdout = %q", out)
	}
	ccAssertNoLeak(t, secret, out, errOut, shown)
	if got, _ := ccVaultGet(t, "default/ai/ccask/api_key"); got != secret {
		t.Fatalf("stored = %q", got)
	}
}

func TestCCConnectCustomTTY_HiddenValue(t *testing.T) {
	ccEnv(t)
	ccScriptLines(t, "tty-svc", "")
	ctl := ccPTY(t)
	prompts := ccCaptureStderr(t)
	secret := ccSecret("ctty")
	if _, err := ctl.WriteString(secret + "\n"); err != nil {
		t.Fatal(err)
	}

	out, errOut, err := ccRun(t, "", "connect", "custom")
	shown := prompts()
	if err != nil {
		t.Fatalf("connect custom: %v (%s)", err, errOut)
	}
	if !strings.Contains(shown, "Enter value for api_key") {
		t.Fatalf("hidden prompt not shown: %q", shown)
	}
	if !strings.Contains(out, "Connected: custom/tty-svc (api_key saved)") {
		t.Fatalf("stdout = %q", out)
	}
	ccAssertNoLeak(t, secret, out, errOut, shown)
	if got, _ := ccVaultGet(t, "default/custom/tty-svc/api_key"); got != secret {
		t.Fatalf("stored = %q", got)
	}
}
