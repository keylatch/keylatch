package audit

import "context"

// Discard is an Emitter that records nothing. A gateway a human started with
// --no-audit uses it so credential reads proceed without an audit log; nothing
// else may substitute it for a real emitter.
type Discard struct{}

// Emit drops e.
func (Discard) Emit(context.Context, Event) error { return nil }
