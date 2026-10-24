package sandbox_test

import (
	"encoding/json"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/harness/sandbox"
)

func parse(t *testing.T, doc string) map[string]any {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal([]byte(doc), &m))
	return m
}

func render(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return string(b)
}

var sockets = []string{"/run/user/1/keylatch/keylatchd.sock", "/run/keylatch/broker.sock"}

func TestHardenFromNothing(t *testing.T) {
	m := map[string]any{}
	changed, err := sandbox.HardenClaudeSettings(m, sockets)
	require.NoError(t, err)
	assert.True(t, changed)
	box := m["sandbox"].(map[string]any)
	assert.Equal(t, false, box["allowUnsandboxedCommands"])
	network := box["network"].(map[string]any)
	assert.Equal(t, true, network["allowLocalBinding"])
	assert.Equal(t, []any{sockets[0], sockets[1]}, network["allowUnixSockets"])
	if runtime.GOOS == "linux" {
		assert.Equal(t, true, network["allowAllUnixSockets"])
	} else {
		assert.NotContains(t, network, "allowAllUnixSockets")
	}

	again, err := sandbox.HardenClaudeSettings(m, sockets)
	require.NoError(t, err)
	assert.False(t, again, "a second merge changes nothing")
}

func TestHardenKeepsTheUsersSettingsAndRemovesOnlyKeylatchExclusions(t *testing.T) {
	m := parse(t, `{"model":"x","sandbox":{"enabled":true,"excludedCommands":["docker:*","keylatch run:*","${HOME}/.local/bin/keylatch call:*","git:*"],"allowUnsandboxedCommands":true,"network":{"allowUnixSockets":["/var/run/docker.sock"],"httpProxyPort":8080}}}`)
	changed, err := sandbox.HardenClaudeSettings(m, sockets[:1])
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, "x", m["model"])
	box := m["sandbox"].(map[string]any)
	assert.Equal(t, true, box["enabled"])
	assert.Equal(t, []any{"docker:*", "git:*"}, box["excludedCommands"])
	assert.Equal(t, false, box["allowUnsandboxedCommands"])
	network := box["network"].(map[string]any)
	assert.Equal(t, []any{"/var/run/docker.sock", sockets[0]}, network["allowUnixSockets"])
	assert.Equal(t, float64(8080), network["httpProxyPort"])
}

func TestHardenDropsAnEmptiedExclusionList(t *testing.T) {
	m := parse(t, `{"sandbox":{"excludedCommands":["keylatch:*"]}}`)
	_, err := sandbox.HardenClaudeSettings(m, nil)
	require.NoError(t, err)
	assert.JSONEq(t, `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false}}`, render(t, m), "no socket given: no network block")
}

func TestHardenRefusesWhatItCannotMerge(t *testing.T) {
	for name, doc := range map[string]string{
		"sandbox not an object":   `{"sandbox":[]}`,
		"excluded not an array":   `{"sandbox":{"excludedCommands":"keylatch"}}`,
		"excluded holds a number": `{"sandbox":{"excludedCommands":[1]}}`,
		"network not an object":   `{"sandbox":{"network":true}}`,
		"sockets not an array":    `{"sandbox":{"network":{"allowUnixSockets":{}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := sandbox.HardenClaudeSettings(parse(t, doc), sockets)
			require.Error(t, err)
		})
	}
}

func TestRemoveClaudeSockets(t *testing.T) {
	m := parse(t, `{"sandbox":{"allowUnsandboxedCommands":false,"network":{"allowLocalBinding":true,"allowUnixSockets":["/var/run/docker.sock","/run/keylatch/broker.sock"]}}}`)
	changed, err := sandbox.RemoveClaudeSockets(m, sockets)
	require.NoError(t, err)
	assert.True(t, changed)
	network := m["sandbox"].(map[string]any)["network"].(map[string]any)
	assert.Equal(t, []any{"/var/run/docker.sock"}, network["allowUnixSockets"])
	assert.Equal(t, false, m["sandbox"].(map[string]any)["allowUnsandboxedCommands"])
	if runtime.GOOS == "linux" {
		assert.Equal(t, false, network["allowAllUnixSockets"])
	}

	m = parse(t, `{"sandbox":{"network":{"allowUnixSockets":["/run/keylatch/broker.sock"]}}}`)
	changed, err = sandbox.RemoveClaudeSockets(m, sockets)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.NotContains(t, m["sandbox"].(map[string]any)["network"], "allowUnixSockets")
}

func TestHardenPreservesAndExtendsStateReadDenies(t *testing.T) {
	m := parse(t, `{"sandbox":{"filesystem":{"denyRead":["~/.ssh"],"denyWrite":["~/src"]}}}`)
	changed, err := sandbox.HardenClaudeSettings(m, nil, "~/.keylatch", "~/.config/keylatch")
	require.NoError(t, err)
	assert.True(t, changed)
	fs := m["sandbox"].(map[string]any)["filesystem"].(map[string]any)
	assert.Equal(t, []any{"~/.ssh", "~/.keylatch", "~/.config/keylatch"}, fs["denyRead"])
	assert.Equal(t, []any{"~/src"}, fs["denyWrite"])
	changed, err = sandbox.HardenClaudeSettings(m, nil, "~/.keylatch", "~/.config/keylatch")
	require.NoError(t, err)
	assert.False(t, changed)
	for _, doc := range []string{`{"sandbox":{"filesystem":false}}`, `{"sandbox":{"filesystem":{"denyRead":[1]}}}`} {
		_, err := sandbox.HardenClaudeSettings(parse(t, doc), nil, "~/.keylatch")
		require.Error(t, err)
	}
}

func TestRemoveClaudeSocketsWithNothingToRemove(t *testing.T) {
	for _, doc := range []string{`{}`, `{"sandbox":{}}`, `{"sandbox":{"network":{}}}`, `{"sandbox":{"network":{"allowUnixSockets":["/other"]}}}`} {
		changed, err := sandbox.RemoveClaudeSockets(parse(t, doc), sockets)
		require.NoError(t, err)
		assert.False(t, changed, doc)
	}
	_, err := sandbox.RemoveClaudeSockets(parse(t, `{"sandbox":{"network":{"allowUnixSockets":3}}}`), sockets)
	require.Error(t, err)
}
