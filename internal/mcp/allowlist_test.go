package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestAllowlistRejections verifies that the per-template allowlist
// rejects dangerous commands while permitting safe ones.
// Uses the specific allowlist from the plan: ["node script.js", "tsx scripts/"]
func TestAllowlistRejections(t *testing.T) {
	// Specific allowlist per plan spec — more restrictive than just "node ".
	allowlist := []string{"node script.js", "tsx scripts/"}

	rejected := []string{
		"python3 -c \"import os; os.system('env')\"",
		"python -c \"import os\"",
		"node -e \"require('child_process').exec('env')\"",
		"perl -e \"system('env')\"",
		"ruby -e \"system('env')\"",
		"deno run -A -e \"console.log(Deno.env.toObject())\"",
		"cat /proc/self/environ",
		"env -0",
		"bash -c \"env\"",
		"sh -c \"printenv\"",
	}

	for _, cmd := range rejected {
		cmd := cmd
		t.Run("reject:"+cmd[:min(20, len(cmd))], func(t *testing.T) {
			assert.False(t, commandMatchesAllowlist(cmd, allowlist),
				"command %q must be rejected by allowlist %v", cmd, allowlist)
		})
	}

	allowed := []string{
		"node script.js",
		"tsx scripts/summarise.ts",
	}
	for _, cmd := range allowed {
		cmd := cmd
		t.Run("allow:"+cmd, func(t *testing.T) {
			assert.True(t, commandMatchesAllowlist(cmd, allowlist),
				"command %q must be allowed by allowlist %v", cmd, allowlist)
		})
	}
}

// TestEmptyAllowlistRejectsEverything verifies that an empty allowlist
// denies every command, including seemingly safe ones.
func TestEmptyAllowlistRejectsEverything(t *testing.T) {
	commands := []string{
		"node script.js",
		"tsx main.ts",
		"echo hello",
		"ls",
		"",
	}
	for _, cmd := range commands {
		assert.False(t, commandMatchesAllowlist(cmd, []string{}),
			"empty allowlist must reject command %q", cmd)
		assert.False(t, commandMatchesAllowlist(cmd, nil),
			"nil allowlist must reject command %q", cmd)
	}
}
