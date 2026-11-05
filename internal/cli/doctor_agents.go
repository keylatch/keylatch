package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/keylatch/keylatch/internal/doctor"
	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/harness/installer"
)

// agentRow is what doctor --agents reports for one harness.
type agentRow struct {
	ID                string                   `json:"id"`
	Name              string                   `json:"name"`
	Support           string                   `json:"support"`
	Detected          bool                     `json:"detected"`
	Hook              string                   `json:"hook"`
	MCP               string                   `json:"mcp"`
	Rules             string                   `json:"rules"`
	Sandbox           string                   `json:"sandbox,omitempty"` // "excluded" when keylatch is in Claude Code's excludedCommands
	HookPath          string                   `json:"hook_path,omitempty"`
	GuardPath         string                   `json:"guard_binary,omitempty"`
	Verified          string                   `json:"verified,omitempty"`
	Problem           string                   `json:"problem,omitempty"`
	LastDrift         *doctor.HarnessDrift     `json:"last_drift,omitempty"`
	DriftState        string                   `json:"drift_state"`
	ConfiguredSandbox string                   `json:"configured_sandbox"`
	SandboxSettings   []doctor.HarnessSettings `json:"sandbox_settings,omitempty"`
	SocketProbe       string                   `json:"sandbox_socket_probe"`
	// fail marks a problem that leaves the agent unguarded or its hook broken.
	fail bool
}

const (
	stateInstalled = "installed"
	stateMissing   = "missing"
	stateNone      = "-"
)

func componentState(c installer.Component) string {
	switch {
	case c.Err != nil:
		return "damaged"
	case c.Present:
		return stateInstalled
	}
	return stateMissing
}

// collectAgents inspects every harness. lookPath and fileExists are the
// machine, replaced in tests.
func collectAgents(env harness.Env, lookPath func(string) (string, error), fileExists func(string) bool) []agentRow {
	var rows []agentRow
	for _, d := range harness.All() {
		row := agentRow{ID: d.ID, Name: d.Name, Support: string(d.Support), Verified: d.Verified, Hook: stateNone, MCP: stateNone, Rules: stateNone, DriftState: "unknown", ConfiguredSandbox: "unknown", SocketProbe: "unknown"}
		onPath := slices.ContainsFunc(d.Executables, func(exe string) bool { _, err := lookPath(exe); return err == nil })
		if d.Support != harness.SupportGuard {
			row.Detected = onPath
			rows = append(rows, row)
			continue
		}
		st := installer.Inspect(d, env)
		row.Detected = st.Detected || onPath
		row.Hook, row.MCP = componentState(st.Hook), componentState(st.MCP)
		row.HookPath, row.GuardPath = st.Hook.Path, st.GuardBinary
		if d.Rules.File != "" {
			row.Rules = componentState(st.Rules)
		}
		switch {
		case st.Hook.Err != nil:
			row.Problem, row.fail = fmt.Sprintf("cannot read %s: %v", st.Hook.Path, st.Hook.Err), true
		case st.Hook.Present && st.GuardBinary != "" && !fileExists(st.GuardBinary):
			row.Problem, row.fail = fmt.Sprintf("the hook runs %s, which does not exist; run keylatch agent install %s --upgrade", st.GuardBinary, d.ID), true
		case row.Detected && !st.Hook.Present:
			row.Problem = fmt.Sprintf("found on this machine without the guard; run keylatch agent install %s", d.ID)
		}
		if d.ID == "claude-code" {
			checkClaudeSandbox(&row, env)
		}
		rows = append(rows, row)
	}
	return rows
}

// checkClaudeSandbox reports keylatch entries in Claude Code's
// sandbox.excludedCommands. An excluded command that can start a child runs it
// outside the sandbox, which leaves the agent unguarded.
func checkClaudeSandbox(row *agentRow, env harness.Env) {
	getenv := env.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	lookup := func(key string) string {
		if key == "HOME" && env.Home != "" {
			return env.Home
		}
		if key == "CLAUDE_PROJECT_DIR" && env.Project != "" {
			return env.Project
		}
		return getenv(key)
	}
	row.ConfiguredSandbox, row.SandboxSettings = doctor.ClaudeCodeSandboxSettings(lookup)
	found, unreadable := doctor.ClaudeCodeExclusions(lookup)
	row.Sandbox = "ok"
	if len(found) == 0 {
		if len(unreadable) > 0 {
			row.Sandbox = "unknown"
			if row.Problem != "" {
				row.Problem += "; "
			}
			row.Problem += "could not read Claude Code settings to check the sandbox: " + strings.Join(unreadable, ", ")
		}
		return
	}
	row.Sandbox = "excluded"
	var entries []string
	for _, e := range found {
		entries = append(entries, fmt.Sprintf("%s: %q", e.File, e.Pattern))
		row.fail = row.fail || e.RunsChildren
	}
	problem := "sandbox.excludedCommands lists keylatch (" + strings.Join(entries, "; ") + "); run keylatch doctor for the fix, or keylatch agent install claude-code --sandbox to remove it"
	if row.Problem != "" {
		problem = row.Problem + "; " + problem
	}
	row.Problem = problem
}

// agentsExit is 0 when every harness found is guarded, 1 when one lacks the
// guard and 2 when a guard that is installed is broken.
func agentsExit(rows []agentRow) int {
	code := doctorExitOK
	for _, r := range rows {
		switch {
		case r.fail:
			return doctorExitFailure
		case r.Problem != "":
			code = doctorExitWarnings
		}
	}
	return code
}

func writeAgents(w io.Writer, rows []agentRow, asJSON bool) error {
	if asJSON {
		b, err := json.MarshalIndent(map[string]any{"agents": rows}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w, string(b))
		return err
	}
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AGENT\tSUPPORT\tFOUND\tHOOK\tMCP\tRULES\tEXCLUSIONS\tCONFIGURED SANDBOX\tSOCKET PROBE\tLAST DRIFT")
	for _, r := range rows {
		found := "no"
		if r.Detected {
			found = "yes"
		}
		sandboxState := r.Sandbox
		if sandboxState == "" {
			sandboxState = stateNone
		}
		drift := r.DriftState
		if r.LastDrift != nil {
			drift = r.LastDrift.Result + " " + r.LastDrift.CheckedAt.Format("2006-01-02T15:04:05Z07:00") + " " + r.LastDrift.Version
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Support, found, r.Hook, r.MCP, r.Rules, sandboxState, r.ConfiguredSandbox, r.SocketProbe, drift)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	for _, r := range rows {
		if r.Problem != "" {
			fmt.Fprintf(w, "\n%s: %s\n", r.Name, r.Problem)
		}
	}
	return nil
}

func runDoctorAgents(w io.Writer, asJSON bool, driftDirs ...string) (int, error) {
	env, err := harness.SystemEnv()
	if err != nil {
		return doctorExitFailure, fmt.Errorf("cannot determine the home directory: %w", err)
	}
	rows := collectAgents(env, exec.LookPath, func(p string) bool { _, err := os.Stat(p); return err == nil })
	if len(driftDirs) > 0 && driftDirs[0] != "" {
		for i := range rows {
			result, err := doctor.ReadHarnessDrift(filepath.Join(driftDirs[0], rows[i].ID+".json"), rows[i].ID)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return doctorExitFailure, fmt.Errorf("%s drift evidence: %w", rows[i].ID, err)
			}
			rows[i].LastDrift, rows[i].DriftState = result, result.Result
		}
	}
	if err := writeAgents(w, rows, asJSON); err != nil {
		return doctorExitFailure, err
	}
	return agentsExit(rows), nil
}
