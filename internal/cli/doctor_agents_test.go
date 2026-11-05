package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/harness/installer"
)

func agentTestEnv(home string) harness.Env {
	return harness.Env{Home: home, Getenv: func(string) string { return "" }}
}

func noExecutables(string) (string, error) { return "", errors.New("not found") }

func installFor(t *testing.T, id, home, bin string, parts installer.Parts) {
	t.Helper()
	d, ok := harness.Lookup(id)
	require.True(t, ok)
	_, err := installer.Install(d, installer.Options{
		Env: agentTestEnv(home), Command: installer.GuardCommand(d, bin), Binary: bin,
		Server: installer.Server{Command: bin}, Parts: parts,
	})
	require.NoError(t, err)
}

func row(t *testing.T, rows []agentRow, id string) agentRow {
	t.Helper()
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no row for %s", id)
	return agentRow{}
}

func TestDoctorAgentsReportsEachHarness(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "bin", "keylatch")
	require.NoError(t, os.MkdirAll(filepath.Dir(bin), 0o700))
	require.NoError(t, os.WriteFile(bin, []byte("x"), 0o700))
	installFor(t, "gemini-cli", home, bin, installer.Parts{})

	rows := collectAgents(agentTestEnv(home), noExecutables, func(p string) bool { _, err := os.Stat(p); return err == nil })
	gemini, codex, aider := row(t, rows, "gemini-cli"), row(t, rows, "codex"), row(t, rows, "aider")
	assert.Equal(t, stateInstalled, gemini.Hook)
	assert.Equal(t, stateInstalled, gemini.MCP)
	assert.Equal(t, stateInstalled, gemini.Rules)
	assert.Equal(t, filepath.ToSlash(bin), gemini.GuardPath, "hook commands use forward slashes on every platform")
	assert.Empty(t, gemini.Problem)
	assert.Equal(t, stateMissing, codex.Hook)
	assert.False(t, codex.Detected)
	assert.Equal(t, stateNone, aider.Hook)
	assert.Equal(t, doctorExitOK, agentsExit(rows))
}

func TestDoctorAgentsFlagsAMissingGuardAndABrokenOne(t *testing.T) {
	home := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".codex"), 0o700))
	rows := collectAgents(agentTestEnv(home), noExecutables, func(string) bool { return true })
	codex := row(t, rows, "codex")
	assert.True(t, codex.Detected)
	assert.Contains(t, codex.Problem, "keylatch agent install codex")
	assert.Equal(t, doctorExitWarnings, agentsExit(rows), "a found agent without the guard is a warning")

	bin := filepath.Join(home, "gone", "keylatch")
	installFor(t, "cursor", home, bin, installer.Parts{Guard: true})
	rows = collectAgents(agentTestEnv(home), noExecutables, func(string) bool { return false })
	cursor := row(t, rows, "cursor")
	assert.Contains(t, cursor.Problem, "does not exist")
	assert.Contains(t, cursor.Problem, "--upgrade")
	assert.Equal(t, doctorExitFailure, agentsExit(rows), "a hook that runs a missing binary fails closed for the agent and is an error here")

	require.NoError(t, os.WriteFile(filepath.Join(home, ".cursor", "hooks.json"), []byte("{"), 0o600))
	rows = collectAgents(agentTestEnv(home), noExecutables, func(string) bool { return true })
	assert.Equal(t, "damaged", row(t, rows, "cursor").Hook)
	assert.Equal(t, doctorExitFailure, agentsExit(rows))
}

func TestDoctorAgentsDetectsByExecutable(t *testing.T) {
	rows := collectAgents(agentTestEnv(t.TempDir()), func(exe string) (string, error) {
		if exe == "aider" || exe == "claude" {
			return "/usr/bin/" + exe, nil
		}
		return "", errors.New("not found")
	}, func(string) bool { return true })
	assert.True(t, row(t, rows, "aider").Detected)
	assert.True(t, row(t, rows, "claude-code").Detected)
	assert.False(t, row(t, rows, "codex").Detected)
}

func TestWriteAgents(t *testing.T) {
	rows := []agentRow{{ID: "codex", Name: "Codex CLI", Support: "guard", Detected: true, Hook: stateMissing, MCP: stateNone, Rules: stateNone, Problem: "found on this machine without the guard"}}
	var table bytes.Buffer
	require.NoError(t, writeAgents(&table, rows, false))
	assert.Contains(t, table.String(), "AGENT")
	assert.Contains(t, table.String(), "Codex CLI: found on this machine without the guard")

	var asJSON bytes.Buffer
	require.NoError(t, writeAgents(&asJSON, rows, true))
	var doc struct {
		Agents []map[string]any `json:"agents"`
	}
	require.NoError(t, json.Unmarshal(asJSON.Bytes(), &doc))
	assert.Equal(t, "codex", doc.Agents[0]["id"])
	assert.Equal(t, true, doc.Agents[0]["detected"])
}

func TestRunDoctorAgentsReadsThisMachine(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	var out bytes.Buffer
	code, err := runDoctorAgents(&out, true)
	require.NoError(t, err)
	assert.Contains(t, []int{doctorExitOK, doctorExitWarnings}, code)
	assert.Contains(t, out.String(), `"claude-code"`)
}
