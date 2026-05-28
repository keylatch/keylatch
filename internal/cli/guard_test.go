package cli_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/cli"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func lookupWith(kv map[string]string) llmcontext.Lookup {
	return func(k string) string { return kv[k] }
}

func makeArgs(env map[string]string) cli.HandlerArgs {
	return cli.HandlerArgs{
		Positional: []string{"test-cmd"},
		Flags:      map[string]string{},
		Env:        lookupWith(env),
		Stdin:      bytes.NewReader(nil),
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
	}
}

func TestGuardLLMSession_BlocksInLLMSession(t *testing.T) {
	callCount := 0
	inner := func(_ context.Context, _ cli.HandlerArgs) (cli.Result, error) {
		callCount++
		return cli.Result{ExitCode: 0, Message: "secret data"}, nil
	}

	var capturedEvent cli.SecurityBlockEvent
	original := cli.SecurityBlockHook
	cli.SecurityBlockHook = func(_ context.Context, e cli.SecurityBlockEvent) {
		capturedEvent = e
	}
	defer func() { cli.SecurityBlockHook = original }()

	guarded := cli.GuardLLMSession(inner)
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	args := cli.HandlerArgs{
		Positional: []string{"get", "svc", "key"},
		Flags:      map[string]string{},
		Env:        lookupWith(map[string]string{"CLAUDE_CODE": "1"}),
		Stdin:      bytes.NewReader(nil),
		Stdout:     stdout,
		Stderr:     stderr,
	}

	res, err := guarded(context.Background(), args)
	require.NoError(t, err)
	assert.Equal(t, exitcode.SecurityBlock, res.ExitCode)
	assert.Equal(t, 0, callCount, "inner handler must not be called in LLM session")
	assert.Empty(t, stdout.String(), "stdout must be empty when blocked")
	assert.Contains(t, stderr.String(), "Blocked in LLM session")
	assert.NotZero(t, capturedEvent.Time)
	assert.Contains(t, capturedEvent.Signals, "CLAUDE_CODE")
}

func TestGuardLLMSession_AllowsOutsideLLMSession(t *testing.T) {
	callCount := 0
	expected := cli.Result{ExitCode: 0, Message: "ok"}
	inner := func(_ context.Context, _ cli.HandlerArgs) (cli.Result, error) {
		callCount++
		return expected, nil
	}

	guarded := cli.GuardLLMSession(inner)
	args := makeArgs(map[string]string{})

	res, err := guarded(context.Background(), args)
	require.NoError(t, err)
	assert.Equal(t, 1, callCount, "inner handler must be called exactly once outside LLM session")
	assert.Equal(t, expected.ExitCode, res.ExitCode)
}

func TestGuardLLMSession_AllSignalsBlock(t *testing.T) {
	for _, envSet := range []map[string]string{
		{"CLAUDE_CODE": "1"},
		{"CODEX_ENV": "1"},
		{"CREDENTIALS_LLM_SESSION": "1"},
	} {
		inner := func(_ context.Context, _ cli.HandlerArgs) (cli.Result, error) {
			return cli.Result{ExitCode: 0}, nil
		}
		guarded := cli.GuardLLMSession(inner)
		args := makeArgs(envSet)
		res, err := guarded(context.Background(), args)
		require.NoError(t, err)
		assert.Equal(t, exitcode.SecurityBlock, res.ExitCode)
	}
}

func TestGuardLLMSession_SecurityBlockHookReceivesEvent(t *testing.T) {
	var events []cli.SecurityBlockEvent
	original := cli.SecurityBlockHook
	cli.SecurityBlockHook = func(_ context.Context, e cli.SecurityBlockEvent) {
		events = append(events, e)
	}
	defer func() { cli.SecurityBlockHook = original }()

	inner := func(_ context.Context, _ cli.HandlerArgs) (cli.Result, error) {
		return cli.Result{ExitCode: 0}, nil
	}
	guarded := cli.GuardLLMSession(inner)
	args := makeArgs(map[string]string{"CLAUDE_CODE": "1"})
	_, _ = guarded(context.Background(), args)

	require.Len(t, events, 1)
	assert.WithinDuration(t, time.Now(), events[0].Time, 5*time.Second)
}

func TestValueBearingHandler_BlocksInLLMSession(t *testing.T) {
	inner := func(_ context.Context, _ cli.HandlerArgs) (cli.Result, error) {
		return cli.Result{ExitCode: 0, Message: "secret"}, nil
	}
	vbh := cli.AsValueBearing(inner)

	args := makeArgs(map[string]string{"CLAUDE_CODE": "1"})
	args.Stdout = &bytes.Buffer{}
	args.Stderr = &bytes.Buffer{}

	res, err := vbh.Invoke(context.Background(), args)
	require.NoError(t, err)
	assert.Equal(t, exitcode.SecurityBlock, res.ExitCode)
}

func TestValueBearingHandler_AllowsOutsideLLMSession(t *testing.T) {
	called := false
	inner := func(_ context.Context, _ cli.HandlerArgs) (cli.Result, error) {
		called = true
		return cli.Result{ExitCode: 0}, nil
	}
	vbh := cli.AsValueBearing(inner)
	args := makeArgs(map[string]string{})
	res, err := vbh.Invoke(context.Background(), args)
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, 0, res.ExitCode)
}
