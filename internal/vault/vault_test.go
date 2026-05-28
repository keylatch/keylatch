package vault_test

import (
	"context"
	"sync"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/keylatch/keylatch/internal/vault"
)

func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// fileBackendEnv returns a fakeEnv for the file backend with a test keyring.
// It calls testutil.SetupTestKeyring which sets KEYLATCH_AGE_IDENTITY and
// KEYLATCH_KEYRING_PATH via t.Setenv, and includes KEYLATCH_KEYRING_PATH in
// the returned env map so dispatch.Select can pass it to the file factory.
func fileBackendEnv(t *testing.T) func(string) string {
	t.Helper()
	krPath := testutil.SetupTestKeyring(t)
	return fakeEnv(map[string]string{"KEYLATCH_KEYRING_PATH": krPath})
}

// recordingEmitter captures emitted audit events for test assertions.
type recordingEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingEmitter) Emit(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recordingEmitter) last() (audit.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == 0 {
		return audit.Event{}, false
	}
	return r.events[len(r.events)-1], true
}

func TestVault_GetSetList_FileBackend(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	env := fileBackendEnv(t)
	ctx := context.Background()

	// Set a value.
	path := "default/ai/openrouter/api_key"
	want := []byte("test-key")
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	if err := vault.Set(ctx, path, want, meta, cfg, env); err != nil {
		t.Fatalf("vault.Set: %v", err)
	}

	// Get the value back.
	got, err := vault.Get(ctx, path, cfg, env)
	if err != nil {
		t.Fatalf("vault.Get: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("vault.Get: got %q, want %q", got, want)
	}

	// List returns the path without values.
	entries, err := vault.List(ctx, "default/ai/", cfg, env)
	if err != nil {
		t.Fatalf("vault.List: %v", err)
	}

	found := false
	for _, e := range entries {
		if e.Path == path {
			found = true
			if !e.Exists {
				t.Error("entry.Exists should be true")
			}
		}
	}
	if !found {
		t.Errorf("vault.List: entry %q not found in %v", path, entries)
	}
}

func TestVault_DispatchErrorPropagates(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "sops" // unknown — will return ErrUnavailable
	env := fakeEnv(map[string]string{})
	ctx := context.Background()

	_, err := vault.Get(ctx, "default/test/key", cfg, env)
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}

// --- T01: Get audit event tests ---

func TestGet_AuditEvent_Success(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	env := fileBackendEnv(t)

	path := "default/ai/openrouter/api_key"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	rec := &recordingEmitter{}
	ctx := audit.WithEmitter(context.Background(), rec)

	// First write so Get succeeds.
	if err := vault.Set(ctx, path, []byte("secret"), meta, cfg, env); err != nil {
		t.Fatalf("vault.Set setup: %v", err)
	}

	_, err := vault.Get(ctx, path, cfg, env)
	if err != nil {
		t.Fatalf("vault.Get: %v", err)
	}

	ev, ok := rec.last()
	if !ok {
		t.Fatal("expected audit event, got none")
	}
	if ev.Action != audit.ActionRead {
		t.Errorf("action: got %q, want %q", ev.Action, audit.ActionRead)
	}
	if ev.Outcome != audit.OutcomeOK {
		t.Errorf("outcome: got %q, want %q", ev.Outcome, audit.OutcomeOK)
	}
	if ev.Path != path {
		t.Errorf("path: got %q, want %q", ev.Path, path)
	}
	if ev.Timestamp.IsZero() {
		t.Error("timestamp must not be zero")
	}
	// S-RM-9: value must never appear in Extra.
	for k, v := range ev.Extra {
		if s, ok := v.(string); ok && s == "secret" {
			t.Errorf("audit Extra[%q] contains credential value", k)
		}
	}
}

func TestGet_AuditEvent_NotFound(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	env := fileBackendEnv(t)

	rec := &recordingEmitter{}
	ctx := audit.WithEmitter(context.Background(), rec)

	_, err := vault.Get(ctx, "default/ai/missing/key", cfg, env)
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}

	ev, ok := rec.last()
	if !ok {
		t.Fatal("expected audit event on failure, got none")
	}
	if ev.Action != audit.ActionRead {
		t.Errorf("action: got %q, want %q", ev.Action, audit.ActionRead)
	}
	if ev.Outcome != audit.OutcomeError {
		t.Errorf("outcome: got %q, want %q", ev.Outcome, audit.OutcomeError)
	}
	if ev.Extra["error_class"] != "not_found" {
		t.Errorf("error_class: got %v, want %q", ev.Extra["error_class"], "not_found")
	}
}

func TestGet_AuditEvent_NilEmitter_NoPanic(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	env := fileBackendEnv(t)
	// No emitter in context — must not panic.
	ctx := context.Background()

	_, _ = vault.Get(ctx, "default/ai/any/key", cfg, env)
}

// --- T02: Set audit event tests ---

func TestSet_AuditEvent_Success(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	env := fileBackendEnv(t)

	path := "default/ai/openrouter/api_key"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	rec := &recordingEmitter{}
	ctx := audit.WithEmitter(context.Background(), rec)

	if err := vault.Set(ctx, path, []byte("my-secret"), meta, cfg, env); err != nil {
		t.Fatalf("vault.Set: %v", err)
	}

	ev, ok := rec.last()
	if !ok {
		t.Fatal("expected audit event, got none")
	}
	if ev.Action != audit.ActionWrite {
		t.Errorf("action: got %q, want %q", ev.Action, audit.ActionWrite)
	}
	if ev.Outcome != audit.OutcomeOK {
		t.Errorf("outcome: got %q, want %q", ev.Outcome, audit.OutcomeOK)
	}
	if ev.Path != path {
		t.Errorf("path: got %q, want %q", ev.Path, path)
	}
	// S-RM-9: value bytes must never appear in Extra.
	for k, v := range ev.Extra {
		if s, ok := v.(string); ok && s == "my-secret" {
			t.Errorf("audit Extra[%q] contains credential value", k)
		}
	}
	if ev.Timestamp.IsZero() {
		t.Error("timestamp must not be zero")
	}
}

func TestSet_NoAuditEvent_WhenDispatchFails(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	// Use an unknown backend so dispatch.Select fails before Set is called.
	// Because vault.Set only emits an audit event after the backend call,
	// a dispatch failure means NO audit event should be emitted.
	cfg := config.Default()
	cfg.Backend = "sops" // unknown
	cfg.DataDir = t.TempDir()
	env := fakeEnv(map[string]string{})

	rec := &recordingEmitter{}
	ctx := audit.WithEmitter(context.Background(), rec)

	_ = vault.Set(ctx, "default/ai/test/key", []byte("v"), backend.Meta{}, cfg, env)

	// dispatch.Select failure: no audit event is emitted (the event is only
	// emitted after the backend call, not when dispatch fails).
	if _, ok := rec.last(); ok {
		t.Error("expected no audit event when dispatch fails, got one")
	}
}

// --- T03: Delete audit event tests ---

func TestDelete_AuditEvent(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	env := fileBackendEnv(t)

	path := "default/ai/openrouter/api_key"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	rec := &recordingEmitter{}
	ctx := audit.WithEmitter(context.Background(), rec)

	// Write first so Delete has something to remove.
	if err := vault.Set(ctx, path, []byte("to-delete"), meta, cfg, env); err != nil {
		t.Fatalf("vault.Set setup: %v", err)
	}

	if err := vault.Delete(ctx, path, cfg, env); err != nil {
		t.Fatalf("vault.Delete: %v", err)
	}

	ev, ok := rec.last()
	if !ok {
		t.Fatal("expected audit event, got none")
	}
	if ev.Action != audit.ActionDelete {
		t.Errorf("action: got %q, want %q", ev.Action, audit.ActionDelete)
	}
	if ev.Outcome != audit.OutcomeOK {
		t.Errorf("outcome: got %q, want %q", ev.Outcome, audit.OutcomeOK)
	}
	if ev.Path != path {
		t.Errorf("path: got %q, want %q", ev.Path, path)
	}
	if ev.Timestamp.IsZero() {
		t.Error("timestamp must not be zero")
	}
}

func TestDelete_AuditEvent_NotFound(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	env := fileBackendEnv(t)

	rec := &recordingEmitter{}
	ctx := audit.WithEmitter(context.Background(), rec)

	err := vault.Delete(ctx, "default/ai/missing/key", cfg, env)
	if err == nil {
		t.Fatal("expected error deleting non-existent key, got nil")
	}

	ev, ok := rec.last()
	if !ok {
		t.Fatal("expected audit event on Delete failure, got none")
	}
	if ev.Action != audit.ActionDelete {
		t.Errorf("action: got %q, want %q", ev.Action, audit.ActionDelete)
	}
	if ev.Outcome != audit.OutcomeError {
		t.Errorf("outcome: got %q, want %q", ev.Outcome, audit.OutcomeError)
	}
	if ev.Extra["error_class"] != "not_found" {
		t.Errorf("error_class: got %v, want %q", ev.Extra["error_class"], "not_found")
	}
}

// --- T04: List audit event tests ---

func TestList_AuditEvent(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	env := fileBackendEnv(t)

	path := "default/ai/openrouter/api_key"
	meta := backend.Meta{Path: path, Backend: "file", Version: 1}

	rec := &recordingEmitter{}
	ctx := audit.WithEmitter(context.Background(), rec)

	// Write one entry so List returns count=1.
	if err := vault.Set(ctx, path, []byte("val"), meta, cfg, env); err != nil {
		t.Fatalf("vault.Set setup: %v", err)
	}

	entries, err := vault.List(ctx, "default/ai/", cfg, env)
	if err != nil {
		t.Fatalf("vault.List: %v", err)
	}

	ev, ok := rec.last()
	if !ok {
		t.Fatal("expected audit event, got none")
	}
	if ev.Action != audit.ActionList {
		t.Errorf("action: got %q, want %q", ev.Action, audit.ActionList)
	}
	if ev.Outcome != audit.OutcomeOK {
		t.Errorf("outcome: got %q, want %q", ev.Outcome, audit.OutcomeOK)
	}
	count, ok := ev.Extra["count"].(int)
	if !ok {
		t.Fatalf("Extra[count] missing or wrong type: %T %v", ev.Extra["count"], ev.Extra["count"])
	}
	if count != len(entries) {
		t.Errorf("Extra[count]: got %d, want %d", count, len(entries))
	}
	if ev.Timestamp.IsZero() {
		t.Error("timestamp must not be zero")
	}
	// Paths (key names) must not appear in Extra — only count.
	for _, e := range entries {
		for k, v := range ev.Extra {
			if s, ok := v.(string); ok && s == e.Path {
				t.Errorf("audit Extra[%q] contains path %q (should be count only)", k, e.Path)
			}
		}
	}
}

func TestList_AuditEvent_NilEmitter_NoPanic(t *testing.T) {
	dispatch.ClearCached()
	defer dispatch.ClearCached()

	cfg := config.Default()
	cfg.Backend = "file"
	cfg.DataDir = t.TempDir()
	env := fileBackendEnv(t)
	ctx := context.Background() // No emitter — must not panic.

	_, _ = vault.List(ctx, "", cfg, env)
}
