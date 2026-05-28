package runner

import "context"

// OK returns true if the context permits returning plaintext credentials.
//
// Phase 1 stub: always returns true. Phase 9 wires real approval checking
// (gateway approval token, runner context key, break-glass flags).
//
// Backends call runner.OK(ctx) before returning plaintext bytes. If false,
// they return backend.ErrLocked.
//
// S1-7: Backend.Get checks this before returning plaintext.
func OK(_ context.Context) bool {
	return true
}
