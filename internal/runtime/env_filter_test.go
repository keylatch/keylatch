package runtime_test

import (
	"context"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/runtime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterChildEnv_StripsKeylatchVars(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"KEYLATCH_DATA_DIR=/home/user/.keylatch/vault",
		"KEYLATCH_BACKEND=file",
		"KEYLATCH_KEYRING_PATH=/home/user/.keylatch/keyring.json",
		"ANTHROPIC_API_KEY=sk-ant-unused",
		"MY_APP_SECRET=should-not-strip",
	}

	filtered := runtime.FilterChildEnv(env)

	assert.Contains(t, filtered, "PATH=/usr/bin")
	assert.Contains(t, filtered, "HOME=/home/user")
	assert.Contains(t, filtered, "ANTHROPIC_API_KEY=sk-ant-unused")
	assert.Contains(t, filtered, "MY_APP_SECRET=should-not-strip")

	for _, e := range filtered {
		key := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			key = e[:i]
		}
		if strings.HasPrefix(key, "KEYLATCH_") {
			t.Errorf("FilterChildEnv left KEYLATCH_ var in output: %s", e)
		}
	}
}

func TestFilterChildEnv_KeepsAllowedKeylatchVars(t *testing.T) {
	env := []string{
		"KEYLATCH_DATA_DIR=/home/user/.keylatch/vault",
		"KEYLATCH_BACKEND=file",
		"KEYLATCH_GATEWAY_TOKEN=tok123",
		"KEYLATCH_GATEWAY_URL=http://127.0.0.1:7878",
		"KEYLATCH_RUNTIME=gateway_typed",
		"PATH=/usr/bin",
	}

	filtered := runtime.FilterChildEnv(env, "KEYLATCH_GATEWAY_TOKEN", "KEYLATCH_GATEWAY_URL")

	assert.Contains(t, filtered, "KEYLATCH_GATEWAY_TOKEN=tok123")
	assert.Contains(t, filtered, "KEYLATCH_GATEWAY_URL=http://127.0.0.1:7878")
	assert.Contains(t, filtered, "PATH=/usr/bin")

	// These should be stripped (not in keep list).
	for _, e := range filtered {
		if e == "KEYLATCH_DATA_DIR=/home/user/.keylatch/vault" {
			t.Error("FilterChildEnv kept KEYLATCH_DATA_DIR which was not in the keep list")
		}
		if e == "KEYLATCH_BACKEND=file" {
			t.Error("FilterChildEnv kept KEYLATCH_BACKEND which was not in the keep list")
		}
		if e == "KEYLATCH_RUNTIME=gateway_typed" {
			t.Error("FilterChildEnv kept KEYLATCH_RUNTIME which was not in the keep list")
		}
	}
}

func TestFilterChildEnv_EmptyEnv(t *testing.T) {
	filtered := runtime.FilterChildEnv(nil)
	assert.Empty(t, filtered)

	filtered = runtime.FilterChildEnv([]string{})
	assert.Empty(t, filtered)
}

func TestFilterChildEnv_NoKeylatchVars(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"TERM=xterm-256color",
	}
	filtered := runtime.FilterChildEnv(env)
	assert.Equal(t, env, filtered)
}

func TestFilterChildEnv_DoesNotModifyInput(t *testing.T) {
	env := []string{
		"KEYLATCH_DATA_DIR=/home/user/.keylatch/vault",
		"PATH=/usr/bin",
	}
	original := make([]string, len(env))
	copy(original, env)

	_ = runtime.FilterChildEnv(env)

	assert.Equal(t, original, env, "FilterChildEnv must not modify the input slice")
}

func TestFilterChildEnv_VarWithNoEquals(t *testing.T) {
	// Edge case: an env entry with no '=' is treated as the whole string being the key.
	env := []string{
		"KEYLATCH_DATA_DIR",
		"PATH=/usr/bin",
	}
	filtered := runtime.FilterChildEnv(env)
	// KEYLATCH_DATA_DIR (no value) must be stripped.
	assert.NotContains(t, filtered, "KEYLATCH_DATA_DIR")
	assert.Contains(t, filtered, "PATH=/usr/bin")
}

// --- CleanBaseEnv tests ---

func TestCleanBaseEnv_RetainsAllowlistedVars(t *testing.T) {
	env := []string{
		"PATH=/usr/bin:/usr/local/bin",
		"HOME=/home/user",
		"USER=alice",
		"LOGNAME=alice",
		"SHELL=/bin/zsh",
		"TERM=xterm-256color",
		"LANG=en_US.UTF-8",
		"TMPDIR=/var/folders/tmp",
		"MY_APP_SECRET=super-secret",
		"KEYLATCH_DATA_DIR=/home/user/.keylatch/vault",
		"KEYLATCH_BACKEND=file",
		"OPENAI_API_KEY=sk-secret",
	}

	clean := runtime.CleanBaseEnv(env)

	assert.Contains(t, clean, "PATH=/usr/bin:/usr/local/bin")
	assert.Contains(t, clean, "HOME=/home/user")
	assert.Contains(t, clean, "USER=alice")
	assert.Contains(t, clean, "LOGNAME=alice")
	assert.Contains(t, clean, "SHELL=/bin/zsh")
	assert.Contains(t, clean, "TERM=xterm-256color")
	assert.Contains(t, clean, "LANG=en_US.UTF-8")
	assert.Contains(t, clean, "TMPDIR=/var/folders/tmp")

	// Secrets and non-allowlisted vars must be stripped.
	assert.NotContains(t, clean, "MY_APP_SECRET=super-secret")
	assert.NotContains(t, clean, "OPENAI_API_KEY=sk-secret")
	assert.NotContains(t, clean, "KEYLATCH_DATA_DIR=/home/user/.keylatch/vault")
	assert.NotContains(t, clean, "KEYLATCH_BACKEND=file")
}

func TestCleanBaseEnv_RetainsLCVars(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"LC_ALL=en_US.UTF-8",
		"LC_CTYPE=en_US.UTF-8",
		"LC_MESSAGES=en_US.UTF-8",
		"SECRET=nope",
	}

	clean := runtime.CleanBaseEnv(env)

	assert.Contains(t, clean, "LC_ALL=en_US.UTF-8")
	assert.Contains(t, clean, "LC_CTYPE=en_US.UTF-8")
	assert.Contains(t, clean, "LC_MESSAGES=en_US.UTF-8")
	assert.NotContains(t, clean, "SECRET=nope")
}

func TestCleanBaseEnv_ExtraVarsPreserved(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"MY_TOKEN=abc123",
		"DEBUG=true",
		"OPENAI_API_KEY=sk-secret",
	}

	// Preserve MY_TOKEN and DEBUG via extra list.
	clean := runtime.CleanBaseEnv(env, "MY_TOKEN", "DEBUG")

	assert.Contains(t, clean, "PATH=/usr/bin")
	assert.Contains(t, clean, "MY_TOKEN=abc123")
	assert.Contains(t, clean, "DEBUG=true")
	// OPENAI_API_KEY was not listed — must be stripped.
	assert.NotContains(t, clean, "OPENAI_API_KEY=sk-secret")
}

func TestCleanBaseEnv_EmptyInput(t *testing.T) {
	assert.Empty(t, runtime.CleanBaseEnv(nil))
	assert.Empty(t, runtime.CleanBaseEnv([]string{}))
}

func TestCleanBaseEnv_DoesNotModifyInput(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"KEYLATCH_BACKEND=file",
		"MY_SECRET=leak",
	}
	original := make([]string, len(env))
	copy(original, env)

	_ = runtime.CleanBaseEnv(env)

	assert.Equal(t, original, env, "CleanBaseEnv must not modify the input slice")
}

// --- Filter() tests ---

// captureEmitter records all emitted audit events.
type captureEmitter struct {
	events []audit.Event
}

func (c *captureEmitter) Emit(_ context.Context, e audit.Event) error {
	c.events = append(c.events, e)
	return nil
}

// TestEnvFilter_StripsAllKEYLATCH verifies that Filter() with default opts removes
// every KEYLATCH_* variable from the child environment.
func TestEnvFilter_StripsAllKEYLATCH(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"KEYLATCH_DATA_DIR=/home/user/.keylatch/vault",
		"KEYLATCH_BACKEND=file",
		"KEYLATCH_CONFIG_DIR=/home/user/.keylatch",
		"MY_APP_VAR=keep-me",
	}

	out := runtime.Filter(context.Background(), env, runtime.FilterOpts{
		Mode: runtime.RuntimeDirectBrokered,
	})

	assert.Contains(t, out, "PATH=/usr/bin")
	assert.Contains(t, out, "HOME=/home/user")
	assert.Contains(t, out, "MY_APP_VAR=keep-me")

	for _, e := range out {
		key := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			key = e[:i]
		}
		if strings.HasPrefix(key, "KEYLATCH_") {
			t.Errorf("Filter left KEYLATCH_ var in output: %s", e)
		}
	}
}

// TestEnvFilter_RetainsGatewayVarsInGatewayModes verifies that Filter() re-injects
// KEYLATCH_GATEWAY_TOKEN and KEYLATCH_GATEWAY_URL in gateway modes.
func TestEnvFilter_RetainsGatewayVarsInGatewayModes(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"KEYLATCH_BACKEND=file",
		"KEYLATCH_DATA_DIR=/home/user/.keylatch/vault",
		// These stale values must be replaced by the injected ones.
		"KEYLATCH_GATEWAY_TOKEN=stale-token",
		"KEYLATCH_GATEWAY_URL=http://old-addr",
	}

	out := runtime.Filter(context.Background(), env, runtime.FilterOpts{
		Mode:         runtime.RuntimeGatewayTyped,
		GatewayToken: "fresh-token",
		GatewayURL:   "http://127.0.0.1:7878",
	})

	assert.Contains(t, out, "KEYLATCH_GATEWAY_TOKEN=fresh-token", "gateway token must be re-injected")
	assert.Contains(t, out, "KEYLATCH_GATEWAY_URL=http://127.0.0.1:7878", "gateway URL must be re-injected")

	// Other KEYLATCH_* vars must be gone.
	for _, e := range out {
		key := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			key = e[:i]
		}
		switch key {
		case "KEYLATCH_GATEWAY_TOKEN", "KEYLATCH_GATEWAY_URL":
			// allowed
		default:
			if strings.HasPrefix(key, "KEYLATCH_") {
				t.Errorf("Filter left unexpected KEYLATCH_ var: %s", e)
			}
		}
	}
}

// TestEnvFilter_BrokeredHasNoKEYLATCH verifies that direct_brokered mode produces
// a child environment with no KEYLATCH_* vars (the driver re-injects only
// KEYLATCH_RUNTIME, which is outside the scope of Filter()).
func TestEnvFilter_BrokeredHasNoKEYLATCH(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"KEYLATCH_BACKEND=file",
		"KEYLATCH_DATA_DIR=/home/user/.keylatch/vault",
		"KEYLATCH_KEYRING_PATH=/home/user/.keylatch/keyring.json",
		"MY_TOKEN=broker-issued-value",
	}

	out := runtime.Filter(context.Background(), env, runtime.FilterOpts{
		Mode: runtime.RuntimeDirectBrokered,
		// No GatewayToken / GatewayURL — brokered mode does not use these.
	})

	assert.Contains(t, out, "PATH=/usr/bin")
	assert.Contains(t, out, "MY_TOKEN=broker-issued-value")

	for _, e := range out {
		key := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			key = e[:i]
		}
		if strings.HasPrefix(key, "KEYLATCH_") {
			t.Errorf("brokered Filter left KEYLATCH_ var in output: %s", e)
		}
	}
}

// TestCleanEnv_StripsAllExceptAllowlist verifies that CleanEnv=true reduces the
// child environment to only the safe base allowlist.
func TestCleanEnv_StripsAllExceptAllowlist(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/user",
		"USER=alice",
		"SHELL=/bin/bash",
		"TERM=xterm-256color",
		"LANG=en_US.UTF-8",
		"TMPDIR=/tmp",
		"MY_APP_SECRET=super-secret",
		"OPENAI_API_KEY=sk-leaked",
		"KEYLATCH_BACKEND=file",
		"KEYLATCH_DATA_DIR=/home/user/.keylatch",
	}

	out := runtime.Filter(context.Background(), env, runtime.FilterOpts{
		Mode:     runtime.RuntimeGatewayTyped,
		CleanEnv: true,
	})

	// Allowlist entries must be preserved.
	assert.Contains(t, out, "PATH=/usr/bin")
	assert.Contains(t, out, "HOME=/home/user")
	assert.Contains(t, out, "USER=alice")
	assert.Contains(t, out, "SHELL=/bin/bash")
	assert.Contains(t, out, "LANG=en_US.UTF-8")
	assert.Contains(t, out, "TMPDIR=/tmp")

	// Non-allowlist entries must be stripped.
	assert.NotContains(t, out, "MY_APP_SECRET=super-secret")
	assert.NotContains(t, out, "OPENAI_API_KEY=sk-leaked")
	assert.NotContains(t, out, "KEYLATCH_BACKEND=file")
	assert.NotContains(t, out, "KEYLATCH_DATA_DIR=/home/user/.keylatch")
}

// TestCleanEnv_ExtraExtendsAllowlist verifies that Extras=["MY_TOKEN"] preserves
// MY_TOKEN even when CleanEnv=true would otherwise strip it.
func TestCleanEnv_ExtraExtendsAllowlist(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"MY_TOKEN=preserved",
		"DEBUG=true",
		"OPENAI_API_KEY=sk-stripped",
	}

	out := runtime.Filter(context.Background(), env, runtime.FilterOpts{
		Mode:     runtime.RuntimeGatewaySDK,
		CleanEnv: true,
		Extras:   []string{"MY_TOKEN", "DEBUG"},
	})

	assert.Contains(t, out, "PATH=/usr/bin")
	assert.Contains(t, out, "MY_TOKEN=preserved")
	assert.Contains(t, out, "DEBUG=true")
	assert.NotContains(t, out, "OPENAI_API_KEY=sk-stripped")
}

// TestFilter_EmitsAuditEvents verifies that Filter() emits both child_env.filter
// and child_env.clean audit events when an emitter is present in the context.
func TestFilter_EmitsAuditEvents(t *testing.T) {
	em := &captureEmitter{}
	ctx := audit.WithEmitter(context.Background(), em)

	env := []string{
		"PATH=/usr/bin",
		"KEYLATCH_BACKEND=file",
		"KEYLATCH_DATA_DIR=/home/user/.keylatch",
		"MY_SECRET=nope",
	}

	_ = runtime.Filter(ctx, env, runtime.FilterOpts{
		Mode:     runtime.RuntimeGatewayTyped,
		CleanEnv: true,
		Extras:   []string{},
	})

	// Expect both child_env.clean and child_env.filter events.
	require.Len(t, em.events, 2, "expected 2 audit events: child_env.clean + child_env.filter")
	actions := map[string]bool{}
	for _, ev := range em.events {
		actions[string(ev.Action)] = true
	}
	assert.True(t, actions[string(audit.ActionCleanEnv)], "child_env.clean event missing")
	assert.True(t, actions[string(audit.ActionChildEnvFilter)], "child_env.filter event missing")
}

// TestFilter_NoAuditWithoutEmitter verifies that Filter() works without panicking
// when no audit emitter is present in the context.
func TestFilter_NoAuditWithoutEmitter(t *testing.T) {
	env := []string{"PATH=/usr/bin", "KEYLATCH_BACKEND=file"}
	// Should not panic.
	out := runtime.Filter(context.Background(), env, runtime.FilterOpts{
		Mode: runtime.RuntimeDirectBrokered,
	})
	assert.Contains(t, out, "PATH=/usr/bin")
	assert.NotContains(t, out, "KEYLATCH_BACKEND=file")
}

// TestFilter_DoesNotModifyInput verifies that Filter() does not mutate the
// caller-supplied parent slice, even when a gateway token replacement occurs
// via appendOrReplaceKV (which modifies its receiver in-place).
func TestFilter_DoesNotModifyInput(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin",
		"KEYLATCH_GATEWAY_TOKEN=stale",
		"KEYLATCH_BACKEND=file",
	}
	original := append([]string{}, parent...) // clone before call

	_ = runtime.Filter(context.Background(), parent, runtime.FilterOpts{
		Mode:         runtime.RuntimeGatewayTyped,
		GatewayToken: "fresh",
		GatewayURL:   "http://127.0.0.1:7878",
	})

	assert.Equal(t, original, parent, "Filter must not mutate the input slice")
}

// TestFilter_NonCleanEnv_EmitsOneEvent verifies that Filter() with CleanEnv=false
// emits exactly one audit event (child_env.filter) and does not emit child_env.clean.
func TestFilter_NonCleanEnv_EmitsOneEvent(t *testing.T) {
	em := &captureEmitter{}
	ctx := audit.WithEmitter(context.Background(), em)

	env := []string{
		"PATH=/usr/bin",
		"KEYLATCH_BACKEND=file",
		"KEYLATCH_DATA_DIR=/home/user/.keylatch",
	}

	_ = runtime.Filter(ctx, env, runtime.FilterOpts{
		Mode:     runtime.RuntimeDirectBrokered,
		CleanEnv: false,
	})

	require.Len(t, em.events, 1, "non-CleanEnv Filter must emit exactly one audit event")
	assert.Equal(t, audit.ActionChildEnvFilter, em.events[0].Action, "the single event must be child_env.filter")
}
