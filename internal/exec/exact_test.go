package exec

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunExactGivesTheChildOnlyTheEnvironmentItIsGiven(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake target is a shell script")
	}
	t.Setenv("KEYLATCH_TEST_LEAK", "leaked")
	script := filepath.Join(t.TempDir(), "probe")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nenv\necho oops >&2\nexit \"${1:-0}\"\n"), 0o755)) //nolint:gosec // G306: a test script

	out, errOut, code, err := RunExact(context.Background(), script, nil, []string{"ONLY=this"})
	require.NoError(t, err)
	assert.Equal(t, 0, code)
	assert.Equal(t, "oops\n", string(errOut))
	assert.NotContains(t, string(out), "KEYLATCH_TEST_LEAK")
	assert.Contains(t, strings.Fields(string(out)), "ONLY=this")

	_, _, code, err = RunExact(context.Background(), script, []string{"3"}, nil)
	require.NoError(t, err, "a non-zero exit is reported through the code, not the error")
	assert.Equal(t, 3, code)
}

func TestRunExactRefusesRelativeAndMissingBinaries(t *testing.T) {
	_, _, _, err := RunExact(context.Background(), "sh", nil, nil)
	assert.ErrorContains(t, err, "relative path rejected")
	_, _, _, err = RunExact(context.Background(), filepath.Join(t.TempDir(), "absent"), nil, nil)
	assert.Error(t, err)
}
