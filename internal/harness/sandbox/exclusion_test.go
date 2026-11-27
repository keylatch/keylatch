package sandbox_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/keylatch/keylatch/internal/harness/sandbox"
)

func TestMatchKeylatch(t *testing.T) {
	for _, tc := range []struct {
		pattern          string
		matches, coversR bool
	}{
		{"keylatch", true, true},
		{"keylatch:*", true, true},
		{"keylatch *", true, true},
		{"/usr/local/bin/keylatch run:*", true, true},
		{"keylatch.exe run:*", true, true},
		{"keylatch run *", true, true},
		{"keylatch launch:*", true, true},
		{"keylatch --quiet run:*", true, true},
		{"keylatch r*", true, true},
		{"keylatch ?un:*", true, true},
		{`C:\tools\keylatch.exe`, true, true},
		{`"C:\Program Files\keylatch\keylatch.exe" run:*`, true, true},
		{`"C:\Program Files\keylatch\keylatch.exe" call:*`, true, false},
		{`"/opt/my apps/keylatch" run:*`, true, true},
		{"keylatch unknownverb:*", true, true},
		{"keylatch mcp proxy:*", true, true},
		{"keylatch call:*", true, false},
		{"keylatch doctor", true, false},
		{"keylatchd:*", false, false},
		{"docker:*", false, false},
		{"echo keylatch", false, false},
		{"", false, false},
	} {
		t.Run(tc.pattern, func(t *testing.T) {
			matches, runs := sandbox.MatchKeylatchOn("linux", tc.pattern)
			assert.Equal(t, tc.matches, matches)
			assert.Equal(t, tc.coversR, runs)
		})
	}
}

func TestMatchKeylatchUsesTheRunningPlatform(t *testing.T) {
	matches, _ := sandbox.MatchKeylatch("keylatch run:*")
	assert.True(t, matches)
}

func TestMatchKeylatchProgramCase(t *testing.T) {
	for goos, want := range map[string]bool{"linux": false, "darwin": true, "windows": true} {
		t.Run(goos, func(t *testing.T) {
			matches, runs := sandbox.MatchKeylatchOn(goos, "KEYLATCH run:*")
			assert.Equal(t, want, matches)
			assert.Equal(t, want, runs)
		})
	}
}

func TestSafeVerbsAreSortedAndNotEmpty(t *testing.T) {
	verbs := sandbox.SafeVerbs()
	assert.Contains(t, verbs, "call")
	assert.NotContains(t, verbs, "run")
	assert.NotContains(t, verbs, "launch")
	assert.IsIncreasing(t, verbs)
}
