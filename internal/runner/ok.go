package runner

import "context"

// OK returns true if the context permits returning plaintext credentials.
//
// Always returns true today; real approval checking (gateway approval token,
// runner context key, break-glass flags) is wired in separately.
//
// Backends call runner.OK(ctx) before returning plaintext bytes. If false,
// they return backend.ErrLocked.
//
// Backend.Get checks this before returning plaintext.
func OK(_ context.Context) bool {
	return true
}
