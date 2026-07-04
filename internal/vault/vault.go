// Package vault is the top layer that maps canonical secret paths to backend
// reads and writes via the dispatcher. It integrates the audit pipeline
// and will integrate policy.
package vault

import (
	"context"
	"errors"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// emitVaultEvent is a nil-safe helper that emits an audit event via the
// emitter stored in ctx (if any). If no emitter is set, or emit returns
// an error, the error is silently discarded — audit failures MUST NOT
// interrupt vault operations (security-in-depth, not hard-dependency).
func emitVaultEvent(ctx context.Context, e audit.Event) {
	em := audit.EmitterFromCtx(ctx)
	if em == nil {
		return
	}
	_ = em.Emit(ctx, e)
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
// The credential value is NEVER included in the event (S-RM-9).
func Get(ctx context.Context, path string, cfg config.Config, env llmcontext.Lookup) ([]byte, error) {
	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return nil, err
	}

	value, _, vaultErr := b.Get(ctx, path)
	outcome := audit.OutcomeOK
	if vaultErr != nil {
		outcome = audit.OutcomeError
	}
	emitVaultEvent(ctx, audit.Event{
		Timestamp: time.Now(),
		Action:    audit.ActionRead,
		Outcome:   outcome,
		Path:      path,
		Extra:     errorClassExtra(vaultErr),
	})
	return value, vaultErr
}

// Set writes value at path via the configured backend.
// The credential value is NEVER included in the audit event (S-RM-9).
//
// Emits ActionWrite audit event on success and failure.
func Set(ctx context.Context, path string, value []byte, meta backend.Meta, cfg config.Config, env llmcontext.Lookup) error {
	b, err := dispatch.Select(ctx, cfg, env)
	if err != nil {
		return err
	}

	vaultErr := b.Set(ctx, path, value, meta)
	outcome := audit.OutcomeOK
	if vaultErr != nil {
		outcome = audit.OutcomeError
	}
	emitVaultEvent(ctx, audit.Event{
		Timestamp: time.Now(),
		Action:    audit.ActionWrite,
		Outcome:   outcome,
		Path:      path,
		Extra:     errorClassExtra(vaultErr),
	})
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

	vaultErr := b.Delete(ctx, path)
	outcome := audit.OutcomeOK
	if vaultErr != nil {
		outcome = audit.OutcomeError
	}
	emitVaultEvent(ctx, audit.Event{
		Timestamp: time.Now(),
		Action:    audit.ActionDelete,
		Outcome:   outcome,
		Path:      path,
		Extra:     errorClassExtra(vaultErr),
	})
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
	// value, so it is safe to log as Path for audit correlation (S-RM-9).
	emitVaultEvent(ctx, audit.Event{
		Timestamp: time.Now(),
		Action:    audit.ActionList,
		Outcome:   outcome,
		Path:      prefix,
		Extra:     extra,
	})
	return entries, vaultErr
}
