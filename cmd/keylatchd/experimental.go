//go:build experimental

package main

// Registers the root-of-trust adapters that exist only in experimental builds.
import _ "github.com/keylatch/keylatch/internal/trust/all"
