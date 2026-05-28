// Package all imports all trust adapter sub-packages so their init() functions
// register themselves with the trust registry.
//
// Usage: blank-import this package in any binary entry point that needs
// trust.Available() to return a non-empty list.
//
//	import _ "github.com/keylatch/keylatch/internal/trust/all"
package all

import (
	_ "github.com/keylatch/keylatch/internal/trust/fido2"
	_ "github.com/keylatch/keylatch/internal/trust/gpgcard"
	_ "github.com/keylatch/keylatch/internal/trust/pkcs11"
	_ "github.com/keylatch/keylatch/internal/trust/secureenclave"
	_ "github.com/keylatch/keylatch/internal/trust/sshagent"
	_ "github.com/keylatch/keylatch/internal/trust/vault"
)
