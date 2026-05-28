// Package all imports all built-in backend packages to trigger their
// self-registration in backend.Default via init() side-effects.
//
// Import this package with a blank identifier in any binary or test that
// needs all backends available:
//
//	import _ "github.com/keylatch/keylatch/internal/backend/all"
package all

import (
	_ "github.com/keylatch/keylatch/internal/backend/awssm"
	_ "github.com/keylatch/keylatch/internal/backend/azurekv"
	_ "github.com/keylatch/keylatch/internal/backend/bw"
	_ "github.com/keylatch/keylatch/internal/backend/doppler"
	_ "github.com/keylatch/keylatch/internal/backend/file"
	_ "github.com/keylatch/keylatch/internal/backend/gcpsm"
	_ "github.com/keylatch/keylatch/internal/backend/infisical"
	_ "github.com/keylatch/keylatch/internal/backend/keeper"
	_ "github.com/keylatch/keylatch/internal/backend/keychain"
	_ "github.com/keylatch/keylatch/internal/backend/lastpass"
	_ "github.com/keylatch/keylatch/internal/backend/op"
	_ "github.com/keylatch/keylatch/internal/backend/opconnect"
	_ "github.com/keylatch/keylatch/internal/backend/protonpass"
	_ "github.com/keylatch/keylatch/internal/backend/vault"
)
