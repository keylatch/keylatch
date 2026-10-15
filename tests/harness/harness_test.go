//go:build harness

package harness

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
	}{
		"claude-code": {
			env:        map[string]string{"CLAUDECODE": "1", "CLAUDE_CODE_ENTRYPOINT": "cli"},
			hookConfig: ".claude/settings.json",
			hooksJSON: func(c string) string {
				return `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + c + `"}]}]}}`
			},
		},
		"codex": {
			env:        map[string]string{"CODEX_SANDBOX": "seatbelt", "CODEX_SANDBOX_NETWORK_DISABLED": "1"},
			hookConfig: ".codex/hooks.json",
			hooksJSON: func(c string) string {
				return `{"hooks":[{"event":"PreToolUse","hooks":[{"type":"command","command":"` + c + `"}]}]}`
			},
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
				assert.Contains(t, string(payload), `"tool_name":"Bash"`)
				assert.Contains(t, string(payload), `"command":"env"`)
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

			t.Run("other exit codes allow the call", func(t *testing.T) {
				install(`exit 1`)
				o := w.agent(name, "Bash", map[string]string{"command": "echo ran"})
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
	for _, id := range []string{"claude-code", "codex"} {
		d, ok := internalharness.Lookup(id)
		require.True(t, ok, "harness %q is registered", id)
		for _, s := range d.Env {
			assert.Contains(t, string(data), `"`+s.Name+`"`, "profile %s must set %s", id, s.Name)
		}
	}
	assert.NotContains(t, string(data), "windsurf", "Windsurf is not a supported harness")
}
