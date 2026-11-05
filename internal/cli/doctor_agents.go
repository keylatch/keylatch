package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"text/tabwriter"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/harness/installer"
)

// agentRow is what doctor --agents reports for one harness.
type agentRow struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Support   string `json:"support"`
	Detected  bool   `json:"detected"`
	Hook      string `json:"hook"`
	MCP       string `json:"mcp"`
	Rules     string `json:"rules"`
	HookPath  string `json:"hook_path,omitempty"`
	GuardPath string `json:"guard_binary,omitempty"`
	Verified  string `json:"verified,omitempty"`
	Problem   string `json:"problem,omitempty"`
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
		row := agentRow{ID: d.ID, Name: d.Name, Support: string(d.Support), Verified: d.Verified, Hook: stateNone, MCP: stateNone, Rules: stateNone}
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
		rows = append(rows, row)
	}
	return rows
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
	fmt.Fprintln(tw, "AGENT\tSUPPORT\tFOUND\tHOOK\tMCP\tRULES")
	for _, r := range rows {
		found := "no"
		if r.Detected {
			found = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Support, found, r.Hook, r.MCP, r.Rules)
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

func runDoctorAgents(w io.Writer, asJSON bool) (int, error) {
	env, err := harness.SystemEnv()
	if err != nil {
		return doctorExitFailure, fmt.Errorf("cannot determine the home directory: %w", err)
	}
	rows := collectAgents(env, exec.LookPath, func(p string) bool { _, err := os.Stat(p); return err == nil })
	if err := writeAgents(w, rows, asJSON); err != nil {
		return doctorExitFailure, err
	}
	return agentsExit(rows), nil
}
