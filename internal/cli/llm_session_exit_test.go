package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/policy"
	"github.com/spf13/cobra"
)

const cdChildArgsEnv = "KEYLATCH_CD_CHILD_ARGS"

// TestCdChildProcess is not a real test: it runs a command tree inside a child
// test binary so commands that call os.Exit can be observed from outside.
func TestCdChildProcess(t *testing.T) {
	raw := os.Getenv(cdChildArgsEnv)
	if raw == "" {
		t.Skip("only runs as a child process")
	}
	root := &cobra.Command{Use: "keylatch", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(newBackendCmd(), newPolicyCmd())
	root.SetArgs(strings.Split(raw, "\x1f"))
	if err := root.ExecuteContext(context.Background()); err != nil {
		os.Stderr.WriteString("child error: " + err.Error() + "\n")
		os.Exit(exitcode.UserError)
	}
	os.Exit(exitcode.OK)
}

// cdRunChild runs args in a child process. llm selects whether an agent
// session signal is present. Returns exit code, stdout and stderr.
func cdRunChild(t *testing.T, llm bool, extraEnv []string, args ...string) (int, string, string) {
	t.Helper()
	if testing.Short() {
		t.Skip("spawns a child test binary")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCdChildProcess$", "-test.count=1") //nolint:gosec // re-executes the test binary itself
	var env []string
	signal := map[string]bool{"KEYLATCH_LLM_TICKET": true, "KEYLATCH_DAEMON_SOCKET": true}
	for _, s := range llmcontext.Signals {
		signal[s.EnvKey] = true
	}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); !signal[k] {
			env = append(env, kv)
		}
	}
	if llm {
		env = append(env, "CREDENTIALS_LLM_SESSION=1")
	}
	env = append(env, cdChildArgsEnv+"="+strings.Join(args, "\x1f"))
	cmd.Env = append(env, extraEnv...)
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run child: %v", err)
	}
	return code, out.String(), errOut.String()
}

func TestAgentSessionBlocksTrustAdminCommands(t *testing.T) {
	dir := t.TempDir()
	krPath := filepath.Join(dir, "keyring.json")
	legacy := []byte(`{"schema_version":1,"kek_type":"passphrase"}`)
	if err := os.WriteFile(krPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		msg  string
	}{
		{"vault init", []string{"backend", "vault", "init", "--addr", "https://vault.invalid", "--transit-key", "k"}, "backend vault init is not permitted"},
		{"vault test", []string{"backend", "vault", "test", "--addr", "https://vault.invalid"}, "backend vault test is not permitted"},
		{"upgrade-trust", []string{"backend", "upgrade-trust", "--keyring", krPath}, "backend upgrade-trust is not permitted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errOut := cdRunChild(t, true, nil, tc.args...)
			if code != exitcode.SecurityBlock {
				t.Fatalf("exit = %d, want %d (stderr %q)", code, exitcode.SecurityBlock, errOut)
			}
			if !strings.Contains(errOut, tc.msg) {
				t.Fatalf("stderr %q missing %q", errOut, tc.msg)
			}
			if strings.Contains(out, "initialized") || strings.Contains(out, "OK") || strings.Contains(out, "upgraded") {
				t.Fatalf("blocked command must not report success: %q", out)
			}
		})
	}
	after, err := os.ReadFile(krPath)
	if err != nil || !bytes.Equal(after, legacy) {
		t.Fatalf("keyring must be untouched by a blocked upgrade: %s (%v)", after, err)
	}
}

func TestAgentSessionBlocksSandboxedRuntimeRule(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := policy.Save(policyPath, policy.Policy{SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: true}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(policyPath)
	code, _, errOut := cdRunChild(t, true, []string{"KEYLATCH_POLICY_PATH=" + policyPath},
		"policy", "allow", "claude", "openai", "--runtime", "direct_classic_sandboxed")
	if code != exitcode.SecurityBlock {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, exitcode.SecurityBlock, errOut)
	}
	if !strings.Contains(errOut, "not permitted inside an LLM session") {
		t.Fatalf("stderr %q missing refusal", errOut)
	}
	after, _ := os.ReadFile(policyPath)
	if !bytes.Equal(before, after) {
		t.Fatal("policy file must not change when the rule is refused")
	}
}

func TestPolicyCheckDenyExitsWithSecurityBlock(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	if err := policy.Save(policyPath, policy.Policy{SchemaVersion: 1, Mode: policy.ModeEnforcing, DefaultDeny: true}); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := cdRunChild(t, false, []string{"KEYLATCH_POLICY_PATH=" + policyPath},
		"policy", "check", "someone", "openai")
	if code != exitcode.SecurityBlock {
		t.Fatalf("exit = %d, want %d (stderr %q)", code, exitcode.SecurityBlock, errOut)
	}
	if !strings.Contains(out, "DENY: no rule matches request") || !strings.Contains(out, "fix: run keylatch policy allow") {
		t.Fatalf("unexpected deny output %q", out)
	}
}
