// Package vault is the top layer that maps canonical secret paths to backend
// reads and writes via the dispatcher. It integrates the audit pipeline
// and will integrate policy.
package vault

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// ErrAuditFailed means a vault operation could not be audited. Reads
// return no value and writes are not attempted when audit is unavailable.
var ErrAuditFailed = errors.New("vault: audit log unavailable; operation refused")

// auditReady checks, before an operation, that the emitter in ctx (if any)
// can record its event.
func auditReady(ctx context.Context) error {
	em := audit.EmitterFromCtx(ctx)
	if em == nil {
		return nil
	}
	if err := audit.Ready(em); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditFailed, err)
	}
	return nil
}

// emitVaultEvent emits e through the emitter stored in ctx, if any. Without
// an emitter it does nothing; an emit failure is returned as ErrAuditFailed.
func emitVaultEvent(ctx context.Context, e audit.Event) error {
	em := audit.EmitterFromCtx(ctx)
	if em == nil {
		return nil
	}
	if err := em.Emit(ctx, e); err != nil {
		return fmt.Errorf("%w: %w", ErrAuditFailed, err)
	}
	return nil
}

// errorClass returns a short, safe description of an error class.
// The raw error message is never included — only the class name.
// This prevents accidental leakage of path fragments or internal details.
func errorClass(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, backend.ErrNotFound) {
		return "not_found"
	}
	return "error"
}

// errorClassExtra returns a non-nil Extra map with "error_class" set when err
// is non-nil, or nil when err is nil.
func errorClassExtra(err error) map[string]any {
	if err == nil {
		return nil
	}
	return map[string]any{"error_class": errorClass(err)}
}

// Get retrieves the plaintext bytes for a canonical path.
// Delegates to the configured backend via dispatch.Select.
// Returns backend.ErrNotFound if the path is absent.
//
// Emits ActionRead audit event on success and failure.
// The credential value is NEVER included in the event.
func Get(ctx context.Context, path string, cfg config.Config, env llmcontext.Lookup) ([]byte, error) {
	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return nil, err
	}

	if err := auditReady(ctx); err != nil {
		return nil, err
	}
	value, _, vaultErr := b.Get(ctx, path)
	outcome := audit.OutcomeOK
	if vaultErr != nil {
		outcome = audit.OutcomeError
	}
	if err := emitVaultEvent(ctx, audit.Event{
		Timestamp: time.Now(),
		Action:    audit.ActionRead,
		Outcome:   outcome,
		Path:      path,
		Extra:     errorClassExtra(vaultErr),
	}); err != nil {
		clear(value)
		return nil, err
	}
	return value, vaultErr
}

// Set writes value at path via the configured backend.
// The credential value is NEVER included in the audit event.
//
// Emits ActionWrite audit event on success and failure.
func Set(ctx context.Context, path string, value []byte, meta backend.Meta, cfg config.Config, env llmcontext.Lookup) error {
	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return err
	}

	if err := auditReady(ctx); err != nil {
		return err
	}
	vaultErr := b.Set(ctx, path, value, meta)
	outcome := audit.OutcomeOK
	if vaultErr != nil {
		outcome = audit.OutcomeError
	}
	if err := emitVaultEvent(ctx, audit.Event{
		Timestamp: time.Now(),
		Action:    audit.ActionWrite,
		Outcome:   outcome,
		Path:      path,
		Extra:     errorClassExtra(vaultErr),
	}); err != nil && vaultErr == nil {
		return err
	}
	return vaultErr
}

// Delete removes the entry at path via the configured backend.
//
// Emits ActionDelete audit event on success and failure.
func Delete(ctx context.Context, path string, cfg config.Config, env llmcontext.Lookup) error {
	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return err
	}

	if err := auditReady(ctx); err != nil {
		return err
	}
	vaultErr := b.Delete(ctx, path)
	outcome := audit.OutcomeOK
	if vaultErr != nil {
		outcome = audit.OutcomeError
	}
	if err := emitVaultEvent(ctx, audit.Event{
		Timestamp: time.Now(),
		Action:    audit.ActionDelete,
		Outcome:   outcome,
		Path:      path,
		Extra:     errorClassExtra(vaultErr),
	}); err != nil && vaultErr == nil {
		return err
	}
	return vaultErr
}

// List returns metadata-only entries for paths matching prefix.
// Delegates to the configured backend via dispatch.Select.
//
// Emits ActionList audit event with count (not the paths themselves).
// Path names are metadata, but count is sufficient for audit purposes.
func List(ctx context.Context, prefix string, cfg config.Config, env llmcontext.Lookup) ([]backend.Entry, error) {
	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return nil, err
	}

	if err := auditReady(ctx); err != nil {
		return nil, err
	}
	entries, vaultErr := b.List(ctx, prefix)
	outcome := audit.OutcomeOK
	if vaultErr != nil {
		outcome = audit.OutcomeError
	}
	extra := errorClassExtra(vaultErr)
	if extra == nil {
		extra = make(map[string]any)
	}
	extra["count"] = len(entries)
	// prefix is a namespace fragment (e.g. "default/ai/"), not a credential
	// value, so it is safe to log as Path for audit correlation.
	if err := emitVaultEvent(ctx, audit.Event{
		Timestamp: time.Now(),
		Action:    audit.ActionList,
		Outcome:   outcome,
		Path:      prefix,
		Extra:     extra,
	}); err != nil {
		return nil, err
	}
	return entries, vaultErr
}
