//go:build harness

package harness

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

const vendorCanary = "vendor-cli-canary-5d0e1f"

func (w *world) expand(s string) string {
	return strings.NewReplacer("{{home}}", w.home, "{{config}}", w.config, "{{canary}}", canarySecret, "{{bin}}", filepath.Join(w.home, "bin")).Replace(s)
}

// leaked reports whether a planted secret, or the raw key-encryption key,
// reached the agent in this call's output.
func (w *world) leaked(o outcome) bool {
	if len(w.identity) > 0 && (bytes.Contains(o.Stdout, w.identity) || bytes.Contains(o.Stderr, w.identity)) {
		return true
	}
	for _, marker := range []string{canarySecret, canarySession, vendorCanary} {
		if strings.Contains(o.text(), marker) {
			return true
		}
	}
	return false
}

// refused reports whether the call was stopped: by the hook, or by Keylatch
// itself refusing an agent (exit code 2).
func refused(o outcome) bool { return o.Blocked || o.ExitCode == 2 }

func (w *world) size(rel string) int64 {
	info, err := os.Stat(filepath.Join(w.config, rel))
	if err != nil {
		return -1
	}
	return info.Size()
}

// baselines records file sizes before the agent acts.
var baselines = map[*world]map[string]int64{}

func (w *world) prepare(name string) {
	w.t.Helper()
	switch name {
	case setupGatewayInit:
		w.must("gateway", "init")
	case setupGatewayToken:
		w.must("gateway", "token", "create", "setup-actor", "--allow", "openai.chat.completion", "--ttl", "1h")
	case setupBWSessionFile:
		w.write(".keylatch/sessions/bw.session", canarySession, 0o600)
	case setupVendorCLIs:
		w.installVendorCLIs()
	case setupAuditBaseline:
		w.baseline("audit.log")
	case setupTokenBaseline:
		w.baseline("gateway-tokens.json")
	case setupSentry:
		w.mustStdin("sentry-harness-token\n", "connect", "sentry", "--non-interactive", "--no-test",
			"--stdin-field", "auth_token", "-f", "org_slug=harness")
	case setupGitHubApp:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			w.t.Fatal(err)
		}
		pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		w.mustStdin(string(pemKey), "connect", "github-app", "--non-interactive", "--no-test",
			"-f", "private_key=@-", "-f", "app_id=1", "-f", "installation_octo=2")
	default:
		w.t.Fatalf("unknown setup %q", name)
	}
}

func (w *world) baseline(rel string) {
	if baselines[w] == nil {
		baselines[w] = map[string]int64{}
	}
	baselines[w][rel] = w.size(rel)
}

func (w *world) grew(rel string) bool {
	before, ok := baselines[w][rel]
	return ok && w.size(rel) > before
}

func (w *world) run(profile string, s scenario) []outcome {
	w.t.Helper()
	for _, name := range s.setup {
		w.prepare(name)
	}
	var outs []outcome
	for _, st := range s.steps {
		in := map[string]string{}
		for k, v := range st.input {
			in[k] = w.expand(v)
		}
		outs = append(outs, w.agent(profile, st.tool, in, s.env...))
	}
	return outs
}

func (w *world) artifact(name string, outs []outcome) bool {
	last := outs[len(outs)-1]
	switch name {
	case artifactKeyMaterialCopied:
		_, idErr := os.Stat(filepath.Join(w.home, "loot", "keyring", "identity"))
		_, krErr := os.Stat(filepath.Join(w.home, "loot", "keyring", "keyring.json"))
		_, vaultErr := os.Stat(filepath.Join(w.home, "loot", "vault", "manifest.json"))
		return idErr == nil && krErr == nil && vaultErr == nil
	case artifactBackupWritten:
		info, err := os.Stat(filepath.Join(w.home, "backup.enc"))
		return err == nil && info.Size() > 0
	case artifactTokenStoreEdited:
		return w.grew("gateway-tokens.json")
	case artifactAuditLogEdited:
		return w.grew("audit.log")
	case artifactUIURLCaptured:
		return strings.Contains(last.text(), "http://127.0.0.1:")
	case artifactMCPRunExecuted:
		text := string(last.Stdout)
		return !refused(last) && strings.Contains(text, `"id":2`) && !strings.Contains(text, "not in allowed_command_prefixes")
	case artifactIdentityListed:
		return strings.Contains(string(last.Stdout), filepath.Join("keyring", "identity"))
	}
	w.t.Fatalf("unknown artifact check %q", name)
	return false
}

func (w *world) verdictOf(s scenario, outs []outcome) verdict {
	leaked := false
	switch s.kind {
	case kindSecret:
		for _, o := range outs {
			if w.leaked(o) {
				leaked = true
			}
		}
	case kindAction:
		leaked = !refused(outs[len(outs)-1])
	case kindArtifact:
		leaked = w.artifact(s.artifact, outs)
	}
	if leaked {
		return wantLeak
	}
	return wantBlocked
}

func TestScenarios(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scenario steps are bash commands; the profile test covers Windows")
	}
	for _, s := range scenarios {
		t.Run(s.id, func(t *testing.T) {
			if s.onlyOS != "" && s.onlyOS != runtime.GOOS {
				t.Skipf("row applies to %s only", s.onlyOS)
			}
			if s.kind == kindContainment {
				assert.Equal(t, s.want, containmentVerdict(t, s.containment), "%s: %s", s.id, s.description)
				return
			}
			w := newWorld(t, "claude-code")
			outs := w.run("claude-code", s)
			got := w.verdictOf(s, outs)
			for i, o := range outs {
				t.Logf("step %d: blocked=%v exit=%d reason=%q\nstdout: %.600q\nstderr: %.600q", i, o.Blocked, o.ExitCode, o.Reason, o.Stdout, o.Stderr)
			}
			assert.Equal(t, s.want, got, "%s: %s", s.id, s.description)
		})
	}
}

var (
	containmentOnce    sync.Once
	containmentResults map[string]string
	containmentOutput  string
)

// containmentVerdict reports the result of one tests/containment test. A
// passing test means the escape it attempts is closed. All rows share one
// `go test` run because each test builds the binaries it needs.
func containmentVerdict(t *testing.T, test string) verdict {
	t.Helper()
	containmentOnce.Do(func() {
		var names []string
		for _, s := range scenarios {
			if s.kind == kindContainment {
				names = append(names, s.containment)
			}
		}
		cmd := exec.Command("go", "test", "-tags", "containment", "-count=1", "-v",
			"-run", "^("+strings.Join(names, "|")+")$", "./tests/containment/")
		cmd.Dir = filepath.Join("..", "..")
		out, _ := cmd.CombinedOutput()
		containmentOutput = string(out)
		containmentResults = map[string]string{}
		for _, line := range strings.Split(containmentOutput, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "---" {
				containmentResults[strings.TrimSuffix(fields[2], ":")] = strings.TrimSuffix(fields[1], ":")
			}
		}
	})
	switch containmentResults[test] {
	case "PASS":
		return wantBlocked
	case "SKIP":
		t.Skipf("%s skipped here", test)
	case "":
		t.Fatalf("%s did not run:\n%s", test, containmentOutput)
	}
	lines := strings.Split(strings.TrimSpace(containmentOutput), "\n")
	t.Logf("%s failed; last output lines:\n%s", test, strings.Join(lines[max(0, len(lines)-15):], "\n"))
	return wantLeak
}

func TestScenarioTableIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range scenarios {
		assert.False(t, seen[s.id], "duplicate scenario id %q", s.id)
		assert.NotEmpty(t, s.description, s.id)
		if s.kind == kindContainment {
			assert.NotEmpty(t, s.containment, s.id)
		} else {
			assert.NotEmpty(t, s.steps, s.id)
		}
		assert.Contains(t, []verdict{wantLeak, wantBlocked}, s.want, s.id)
		if s.kind == kindArtifact {
			assert.NotEmpty(t, s.artifact, s.id)
		}
		seen[s.id] = true
	}
}

// TestDumpWorld lists the files of a bootstrapped world; run it with
// HARNESS_DUMP=1 -v when adding a scenario that touches state on disk.
func TestDumpWorld(t *testing.T) {
	if os.Getenv("HARNESS_DUMP") == "" {
		t.Skip("set HARNESS_DUMP=1 to list the world")
	}
	w := newWorld(t, "claude-code")
	w.must("gateway", "init")
	_ = filepath.WalkDir(w.home, func(p string, d fs.DirEntry, err error) error {
		if err == nil {
			rel, _ := filepath.Rel(w.home, p)
			t.Log(rel)
		}
		return nil
	})
	for _, rel := range []string{"keyring/identity", "keyring/identity.insecure"} {
		data, _ := os.ReadFile(filepath.Join(w.config, rel))
		t.Logf("%s: %.40q", rel, data)
	}
}
