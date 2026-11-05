package runner_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/runner"
)

var serviceSecret = "service" + "-secret-" + "0b7e"

// TestServiceHelperProcess is the command the service driver runs in these
// tests: the test binary itself, which behaves per HELPER_MODE.
func TestServiceHelperProcess(t *testing.T) {
	mode := os.Getenv("HELPER_MODE")
	if mode == "" {
		t.Skip("only runs as a child of the service driver tests")
	}
	switch mode {
	case "check":
		switch {
		case os.Getenv("SVC_VAR") != os.Getenv("HELPER_WANT"):
			os.Exit(3)
		case os.Getenv("KEYLATCH_LEAK") != "":
			os.Exit(4)
		case os.Getenv("KEYLATCH_RUNTIME") != "service":
			os.Exit(5)
		}
		_, _ = os.Stdout.WriteString("echo " + os.Getenv("SVC_VAR") + "\n")
		os.Exit(0)
	case "exit7":
		os.Exit(7)
	}
	os.Exit(9)
}

type fakeReleaser struct {
	got  [][]byte
	conn string
	env  []runner.ServiceEnv
	err  error
}

func (f *fakeReleaser) Release(_ context.Context, connection string, capability []byte) ([]runner.ServiceEnv, error) {
	f.conn = connection
	f.got = append(f.got, append([]byte(nil), capability...))
	if f.err != nil {
		return nil, f.err
	}
	return f.env, nil
}

func serviceRun(t *testing.T, mode string, rel *fakeReleaser, mutate func(*runner.ServiceRun)) (int, string, error) {
	t.Helper()
	dir := t.TempDir()
	capability := bytes.Repeat([]byte{7}, 32)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "keylatch-app-db"), capability, 0o600))
	t.Setenv("HELPER_MODE", mode)
	var out bytes.Buffer
	r := runner.ServiceRun{
		Connection: "app-db", Command: []string{os.Args[0], "-test.run=^TestServiceHelperProcess$"},
		CredentialsDir: dir, Releaser: rel,
		Env:    append(os.Environ(), "KEYLATCH_LEAK=1", "HELPER_WANT="+serviceSecret),
		Stdout: &out, Stderr: &out,
	}
	if mutate != nil {
		mutate(&r)
	}
	code, err := runner.RunService(context.Background(), r)
	return code, out.String(), err
}

func TestServiceRunInjectsAndRedacts(t *testing.T) {
	rel := &fakeReleaser{env: []runner.ServiceEnv{{Name: "SVC_VAR", Value: []byte(serviceSecret)}}}
	code, out, err := serviceRun(t, "check", rel, nil)
	require.NoError(t, err)
	assert.Equal(t, 0, code, "the command saw the value, no KEYLATCH_* variable and KEYLATCH_RUNTIME=service")
	assert.Equal(t, "app-db", rel.conn)
	assert.Equal(t, bytes.Repeat([]byte{7}, 32), rel.got[0], "the capability is the credential file's content")
	assert.NotContains(t, out, serviceSecret, "output is redacted for the value")
	assert.Contains(t, out, "echo")
}

func TestServiceRunExitCodesAndRefusal(t *testing.T) {
	rel := &fakeReleaser{env: []runner.ServiceEnv{{Name: "SVC_VAR", Value: []byte("x")}}}
	code, _, err := serviceRun(t, "exit7", rel, nil)
	require.NoError(t, err)
	assert.Equal(t, 7, code)

	marker := filepath.Join(t.TempDir(), "started")
	refused := &fakeReleaser{err: runner.ErrReleaseRefused}
	code, _, err = serviceRun(t, "check", refused, func(r *runner.ServiceRun) { r.Env = append(r.Env, "MARKER="+marker) })
	assert.ErrorIs(t, err, runner.ErrReleaseRefused)
	assert.Equal(t, exitcode.SecurityBlock, code)
	_, statErr := os.Stat(marker)
	assert.Error(t, statErr, "nothing runs when the broker refuses")

	code, _, err = serviceRun(t, "check", &fakeReleaser{err: errors.New("socket closed")}, nil)
	assert.Error(t, err)
	assert.Equal(t, exitcode.OperationFailed, code)

	code, _, err = serviceRun(t, "check", &fakeReleaser{env: []runner.ServiceEnv{{Name: "SVC_VAR", Value: []byte("y")}}}, func(r *runner.ServiceRun) {
		r.Command = []string{filepath.Join(t.TempDir(), "no-such-command")}
	})
	assert.Error(t, err)
	assert.Equal(t, 127, code)
}

func TestServiceRunRefusesBadSetups(t *testing.T) {
	rel := &fakeReleaser{}
	for name, mutate := range map[string]func(*runner.ServiceRun){
		"no credentials directory": func(r *runner.ServiceRun) { r.CredentialsDir = "" },
		"no credential file":       func(r *runner.ServiceRun) { r.CredentialsDir = t.TempDir() },
		"bad connection":           func(r *runner.ServiceRun) { r.Connection = "../etc/passwd" },
		"no command":               func(r *runner.ServiceRun) { r.Command = nil },
		"wrong length": func(r *runner.ServiceRun) {
			dir := t.TempDir()
			_ = os.WriteFile(filepath.Join(dir, "keylatch-app-db"), []byte("short"), 0o600)
			r.CredentialsDir = dir
		},
	} {
		code, _, err := serviceRun(t, "check", rel, mutate)
		assert.Error(t, err, name)
		assert.Equal(t, exitcode.UserError, code, name)
	}
	assert.Empty(t, rel.got, "a bad setup never reaches the broker")
	assert.True(t, strings.HasPrefix(runner.ServiceCredentialName("x"), "keylatch-"))
}
