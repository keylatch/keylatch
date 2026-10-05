package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/stretchr/testify/require"
)

const launchHelperEnv = "KEYLATCH_LAUNCH_TEST_HELPER"

func isolatedLaunchEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", dir)
	t.Setenv("KEYLATCH_KEYRING_DIR", "")
	testutil.ClearLLMSessionEnv(t)
	return dir
}

// TestLaunchHelperProcess is the harness started by TestLaunchIssuesTicket.
// It prints the doctor report's agent_session field.
func TestLaunchHelperProcess(t *testing.T) {
	if os.Getenv(launchHelperEnv) != "1" {
		t.Skip("helper process for TestLaunchIssuesTicket")
	}
	report, err := doctor.Run(context.Background(), doctor.Options{JSON: true, Env: llmcontext.DefaultLookup})
	require.NoError(t, err)
	out, err := json.Marshal(report)
	require.NoError(t, err)
	fmt.Printf("doctor-json=%s\n", out)
}

func TestLaunchIssuesTicket(t *testing.T) {
	if os.Getenv(launchHelperEnv) == "1" {
		t.Skip("running as the launched harness")
	}
	isolatedLaunchEnv(t)
	withInteractiveStdin(t, true)
	t.Setenv(launchHelperEnv, "1")

	cmd := newLaunchCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"--harness", "claude-code", "--", os.Args[0], "-test.run=^TestLaunchHelperProcess$"})
	require.NoError(t, cmd.ExecuteContext(context.Background()), out.String())

	var line string
	for _, l := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(l, "doctor-json=") {
			line = strings.TrimPrefix(l, "doctor-json=")
		}
	}
	require.NotEmpty(t, line, "harness output:\n%s", out.String())
	var report struct {
		AgentSession struct {
			Detected bool     `json:"detected"`
			Signals  []string `json:"signals"`
			Harness  string   `json:"harness"`
		} `json:"agent_session"`
	}
	require.NoError(t, json.Unmarshal([]byte(line), &report))
	require.True(t, report.AgentSession.Detected)
	require.Contains(t, report.AgentSession.Signals, llmcontext.SignalTicket)
	require.Equal(t, "claude-code", report.AgentSession.Harness)

	info, err := os.Stat(paths.SessionTicketKey(llmcontext.DefaultLookup))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestForgedTicketRejected(t *testing.T) {
	dir := isolatedLaunchEnv(t)
	env := llmcontext.DefaultLookup

	valid, err := issueLaunchTicket(env, "codex")
	require.NoError(t, err)
	withTicket := func(raw string) llmcontext.Lookup {
		return func(k string) string {
			if k == llmcontext.TicketEnv {
				return raw
			}
			return env(k)
		}
	}
	cl := llmcontext.Classify(withTicket(valid))
	require.True(t, slices.Contains(cl.Signals, llmcontext.SignalTicket), "a valid ticket is a positive signal: %v", cl.Signals)
	require.Equal(t, "codex", cl.Harness)

	self, err := llmcontext.CurrentProcess()
	require.NoError(t, err)
	otherKey := bytes.Repeat([]byte{7}, ticketKeySize)
	forged, err := llmcontext.IssueTicket(llmcontext.Ticket{SessionID: "x", Harness: "codex", PID: self.PID, ProcessStart: self.Start}, otherKey)
	require.NoError(t, err)
	_, err = verifySessionTicket(env, forged)
	require.ErrorIs(t, err, llmcontext.ErrTicketInvalid)
	require.False(t, llmcontext.Classify(withTicket(forged)).Detected())

	require.NoError(t, os.Remove(filepath.Join(dir, "keyring", "session-ticket.key")))
	require.False(t, llmcontext.Classify(withTicket(valid)).Detected(), "a ticket without its key changes nothing")
}

func TestLaunchRefusesInsideAgent(t *testing.T) {
	isolatedLaunchEnv(t)
	withInteractiveStdin(t, true)

	run := func(args ...string) error {
		cmd := newLaunchCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs(args)
		return cmd.ExecuteContext(context.Background())
	}

	t.Setenv("CLAUDECODE", "1")
	err := run("--", "claude")
	var cliErr *CLIError
	require.ErrorAs(t, err, &cliErr)
	require.Equal(t, exitcode.SecurityBlock, cliErr.Code)
	require.Contains(t, err.Error(), "CLAUDECODE")
	t.Setenv("CLAUDECODE", "")

	withInteractiveStdin(t, false)
	require.ErrorAs(t, run("--", "claude"), &cliErr)
	require.Equal(t, exitcode.SecurityBlock, cliErr.Code)

	withInteractiveStdin(t, true)
	require.ErrorAs(t, run("--", "vim"), &cliErr)
	require.Equal(t, exitcode.UserError, cliErr.Code)
	require.ErrorAs(t, run("--harness", "windsurf", "--", "claude"), &cliErr)
	require.Equal(t, exitcode.UserError, cliErr.Code)

	_, err = os.Stat(paths.SessionTicketKey(llmcontext.DefaultLookup))
	require.True(t, errors.Is(err, os.ErrNotExist), "a refused launch must not create the ticket key")
}

func TestLaunchEnvironmentReplacesTicket(t *testing.T) {
	env := launchEnvironment([]string{"PATH=/usr/bin", llmcontext.TicketEnv + "=old", "HOME=/home/test"}, "new")
	require.Equal(t, []string{"PATH=/usr/bin", "HOME=/home/test", llmcontext.TicketEnv + "=new"}, env)
}

func TestLoadOrCreateTicketKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring", "session-ticket.key")
	first, err := loadOrCreateTicketKey(path)
	require.NoError(t, err)
	require.Len(t, first, ticketKeySize)
	second, err := loadOrCreateTicketKey(path)
	require.NoError(t, err)
	require.Equal(t, first, second)

	require.NoError(t, os.WriteFile(path, []byte("short"), 0o600))
	_, err = loadOrCreateTicketKey(path)
	require.Error(t, err)
}

func TestResolveLaunchHarness(t *testing.T) {
	for flag, want := range map[string]string{"": "claude-code", "codex": "codex"} {
		got, err := resolveLaunchHarness(flag, "/usr/local/bin/claude")
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
}

func TestDoctorJSONReportsAgentSession(t *testing.T) {
	isolatedLaunchEnv(t)
	t.Setenv("CLAUDECODE", "1")
	report, err := doctor.Run(context.Background(), doctor.Options{JSON: true, Env: llmcontext.DefaultLookup})
	require.NoError(t, err)
	out, err := json.Marshal(buildDoctorJSONV1(report, 0))
	require.NoError(t, err)
	var v1 struct {
		AgentSession doctor.AgentSession `json:"agent_session"`
	}
	require.NoError(t, json.Unmarshal(out, &v1))
	require.Equal(t, doctor.AgentSession{Detected: true, Signals: []string{"CLAUDECODE"}, Harness: "claude-code"}, v1.AgentSession)
}
