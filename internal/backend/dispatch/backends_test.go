// Package dispatch_test imports all built-in backends so that the registry
// is populated when dispatch tests run.
package dispatch_test

import (
	_ "github.com/keylatch/keylatch/internal/backend/all"
)
