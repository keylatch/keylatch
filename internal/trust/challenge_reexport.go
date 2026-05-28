package trust

import "github.com/keylatch/keylatch/internal/trust/challenge"

// Re-exported types and constants from internal/trust/challenge.
// CLI code that only needs challenge functionality can import internal/trust
// instead of internal/trust/challenge.

// Challenge is the Phase 11 ephemeral challenge for root-of-trust approval flows.
type Challenge = challenge.Challenge

// Bind controls what context is bound into a Challenge.
type Bind = challenge.Bind

// Bind constants for trust challenges.
const (
	BindNone    = challenge.BindNone
	BindCommand = challenge.BindCommand
	BindCWD     = challenge.BindCWD
	BindFull    = challenge.BindFull
)

// NewChallenge constructs a new Challenge.
var NewChallenge = challenge.New
