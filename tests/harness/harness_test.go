//go:build harness

package harness

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalharness "github.com/keylatch/keylatch/internal/harness"
)

// TestFakeAgentProfiles checks that each fake agent sets the environment its
// real harness sets, hands the tool call to the installed hook as a JSON
// payload on stdin, and honors both ways a hook can refuse the call.
func TestFakeAgentProfiles(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("hooks run through bash")
	}
	cases := map[string]struct {
		env        map[string]string
		hookConfig string
		hooksJSON  func(command string) string
		// payload is what the hook must find in the call it is handed.
		payload []string
		// failClosed is set for a harness whose hook runner refuses the call
		// when the hook fails for any reason, as an OpenCode plugin does by
		// throwing.
		failClosed bool
	}{
		"claude-code": {
			env:        map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_ENTRYPOINT": "cli"},
			hookConfig: ".claude/settings.json",
			hooksJSON: func(c string) string {
				return `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + c + `"}]}]}}`
			},
			payload: []string{`"tool_name":"Bash"`, `"command":"env"`},
		},
		"codex": {
			env:        map[string]string{"CODEX_SANDBOX": "seatbelt", "CODEX_SANDBOX_NETWORK_DISABLED": "1"},
			hookConfig: ".codex/hooks.json",
			hooksJSON: func(c string) string {
				return `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + c + `"}]}]}}`
			},
			payload: []string{`"tool_name":"Bash"`, `"command":"env"`},
		},
		"cursor": {
			env:        map[string]string{"CURSOR_AGENT": "1"},
			hookConfig: ".cursor/hooks.json",
			hooksJSON: func(c string) string {
				return `{"version":1,"hooks":{"beforeShellExecution":[{"command":"` + c + `"}]}}`
			},
			payload: []string{`"command":"env"`, `"cwd"`},
		},
		"gemini-cli": {
			env:        map[string]string{"GEMINI_CLI": "1"},
			hookConfig: ".gemini/settings.json",
			hooksJSON: func(c string) string {
				return `{"hooks":{"BeforeTool":[{"matcher":"run_shell_command","hooks":[{"type":"command","command":"` + c + `"}]}]}}`
			},
			payload: []string{`"tool_name":"run_shell_command"`, `"command":"env"`},
		},
		"opencode": {
			env:        map[string]string{"OPENCODE": "1"},
			hookConfig: ".config/opencode/plugins/keylatch-guard.ts",
			hooksJSON: func(c string) string {
				return `import { spawnSync } from "node:child_process";` + "\nconst KEYLATCH = \"" + c + "\";\n"
			},
			payload:    []string{`"tool_name":"bash"`, `"command":"env"`},
			failClosed: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			w := &world{t: t, home: home, config: filepath.Join(home, ".keylatch")}
			payloadFile := filepath.Join(home, "payload.json")

			install := func(script string) {
				hook := filepath.Join(home, "hook.sh")
				require.NoError(t, os.WriteFile(hook, []byte("#!/bin/bash\n"+script+"\n"), 0o700))
				cfg := filepath.Join(home, tc.hookConfig)
				require.NoError(t, os.MkdirAll(filepath.Dir(cfg), 0o700))
				require.NoError(t, os.WriteFile(cfg, []byte(tc.hooksJSON(filepath.ToSlash(hook))), 0o600))
			}

			t.Run("environment and payload", func(t *testing.T) {
				install(`cat > ` + filepath.ToSlash(payloadFile))
				o := w.agent(name, "Bash", map[string]string{"command": "env"})
				require.False(t, o.Blocked)
				for k, v := range tc.env {
					assert.Contains(t, string(o.Stdout), k+"="+v, "profile %s must set %s", name, k)
				}
				payload, err := os.ReadFile(payloadFile)
				require.NoError(t, err)
				for _, want := range tc.payload {
					assert.Contains(t, string(payload), want)
				}
			})

			t.Run("exit code 2 blocks", func(t *testing.T) {
				install(`echo refused >&2; exit 2`)
				o := w.agent(name, "Bash", map[string]string{"command": "echo ran"})
				assert.True(t, o.Blocked)
				assert.NotContains(t, string(o.Stdout), "ran")
			})

			t.Run("permissionDecision deny blocks", func(t *testing.T) {
				install(`echo '{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"no"}}'`)
				o := w.agent(name, "Bash", map[string]string{"command": "echo ran"})
				assert.True(t, o.Blocked)
				assert.Equal(t, "no", o.Reason)
			})

			t.Run("other exit codes", func(t *testing.T) {
				install(`exit 1`)
				o := w.agent(name, "Bash", map[string]string{"command": "echo ran"})
				if tc.failClosed {
					assert.True(t, o.Blocked, "a failing hook blocks the call")
					assert.NotContains(t, string(o.Stdout), "ran")
					return
				}
				assert.False(t, o.Blocked)
				assert.Contains(t, string(o.Stdout), "ran")
			})

			t.Run("doctor reports the agent session", func(t *testing.T) {
				install(`exit 0`)
				o := w.agent(name, "Bash", map[string]string{"command": "keylatch doctor --json"})
				var report struct {
					AgentSession struct {
						Detected bool   `json:"detected"`
						Harness  string `json:"harness"`
					} `json:"agent_session"`
				}
				require.NoError(t, json.Unmarshal(o.Stdout, &report), "stdout: %s stderr: %s", o.Stdout, o.Stderr)
				assert.True(t, report.AgentSession.Detected)
				assert.Equal(t, name, report.AgentSession.Harness)
			})
		})
	}
}

// TestProfilesMatchTheHarnessRegistry keeps the recorded environments in step
// with the harness descriptors detection is built from.
func TestProfilesMatchTheHarnessRegistry(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("fakeagent", "profiles.json"))
	require.NoError(t, err)
	for _, id := range []string{"claude-code", "codex", "cursor", "gemini-cli", "opencode"} {
		d, ok := internalharness.Lookup(id)
		require.True(t, ok, "harness %q is registered", id)
		for _, s := range d.Env {
			assert.Contains(t, string(data), `"`+s.Name+`"`, "profile %s must set %s", id, s.Name)
		}
		assert.Contains(t, string(data), `"`+d.Hook.File+`"`, "profile %s names the hook file the installer writes", id)
	}
	assert.NotContains(t, string(data), "aider", "Aider has no hook for a fake agent to run")
}

// TestFakeAgentProfilesBlockTheDenyCorpus installs the guard the way a user
// does and offers every denied command to each harness's fake agent.
func TestFakeAgentProfilesBlockTheDenyCorpus(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("hooks run through bash")
	}
	corpus := readCorpus(t, filepath.Join("..", "..", "internal", "guard", "hook", "testdata", "deny_corpus.txt"))
	require.NotEmpty(t, corpus)
	for _, id := range []string{"claude-code", "codex", "cursor", "gemini-cli", "opencode"} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()
			home := t.TempDir()
			w := &world{t: t, home: home, config: filepath.Join(home, ".keylatch")}
			w.must("agent", "install", id, "--guard")
			// The corpus is written for a fixed home and binary path; the guard
			// protects the real ones.
			swap := strings.NewReplacer("/home/tester", filepath.ToSlash(home), "/usr/local/bin/keylatch", filepath.ToSlash(binaries.keylatch))
			for _, cmd := range corpus {
				cmd = swap.Replace(cmd)
				o := w.offer(id, "Bash", map[string]string{"command": cmd})
				if !o.Blocked {
					t.Errorf("%s let %q through", id, cmd)
				}
			}
			allowed := w.offer(id, "Bash", map[string]string{"command": "echo harmless"})
			assert.False(t, allowed.Blocked, "the guard does not refuse an ordinary command: %s", allowed.Reason)
		})
	}
}

func readCorpus(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var lines []string
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, strings.ReplaceAll(line, `\n`, "\n"))
	}
	return lines
}
