package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The dangerous commands an agent might ask for are refused by the allowlist
// whatever form they take; see TestMCPExactAllowlist for the matching rules.
func TestAllowlistRejections(t *testing.T) {
	provider, _ := shellProvider(t, "mcp-allowlist-rejections", "sh script.js", "sh scripts/")

	rejected := []any{
		"python3 -c \"import os; os.system('env')\"",
		"node -e \"require('child_process').exec('env')\"",
		"perl -e \"system('env')\"",
		"cat /proc/self/environ",
		"env -0",
		"bash -c \"env\"",
		"sh -c \"printenv\"",
		[]any{"sh", "-c", "printenv"},
		[]any{"/bin/bash", "-c", "env"},
	}
	for _, cmd := range rejected {
		d := &stubDispatcher{}
		_, isErr := callRunHandler(t, newMockStore(), d, map[string]any{"provider": provider, "command": cmd})
		assert.True(t, isErr, "%v must be rejected", cmd)
		assert.Zero(t, d.calls, "%v must not reach the dispatcher", cmd)
	}

	for _, cmd := range []any{"sh script.js", []any{"sh", "script.js", "--flag"}, "sh scripts/summarise.sh"} {
		d := &stubDispatcher{}
		_, isErr := callRunHandler(t, newMockStore(), d, map[string]any{"provider": provider, "command": cmd})
		assert.False(t, isErr, "%v must be allowed", cmd)
		assert.Equal(t, 1, d.calls)
	}
}

// A provider with no allowed commands refuses everything.
func TestEmptyAllowlistRejectsEverything(t *testing.T) {
	provider, _ := shellProvider(t, "mcp-allowlist-empty")
	for _, cmd := range []any{"sh -c true", []any{"sh"}, "echo hello", "ls"} {
		d := &stubDispatcher{}
		_, isErr := callRunHandler(t, newMockStore(), d, map[string]any{"provider": provider, "command": cmd})
		assert.True(t, isErr, "empty allowlist must reject %v", cmd)
		assert.Zero(t, d.calls)
	}
}
