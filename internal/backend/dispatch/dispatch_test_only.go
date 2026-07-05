//go:build test_only

// Package dispatch — test-only helpers.
//
// This file is compiled ONLY when -tags test_only is passed to go test/build.
// It provides a Reset() alias for ClearCached() so existing test code can
// continue to use the familiar Reset() name without exposing it in production
// binaries.
//
// `nm ./keylatch | grep -i reset` must return empty; the symbol
// must not be reachable from the production build graph.
package dispatch

// Reset clears the cached backend instance and sync.Once state.
// Alias for ClearCached() — test-only build tag ensures this symbol is never
// linked into the production keylatch binary.
//
// Deprecated for new code: prefer ClearCached() which compiles in all builds.
func Reset() {
	ClearCached()
}
