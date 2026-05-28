package audit

import "context"

// emitterKey is the unexported context key for an audit.Emitter.
type emitterKey struct{}

// WithEmitter returns a new context that carries emitter.
// Retrieve it with EmitterFromCtx.
func WithEmitter(ctx context.Context, emitter Emitter) context.Context {
	return context.WithValue(ctx, emitterKey{}, emitter)
}

// EmitterFromCtx returns the Emitter stored in ctx, or nil if none is set.
// Callers must nil-check before emitting.
func EmitterFromCtx(ctx context.Context) Emitter {
	if e, ok := ctx.Value(emitterKey{}).(Emitter); ok {
		return e
	}
	return nil
}
