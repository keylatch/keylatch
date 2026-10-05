package cli

import (
	"errors"

	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// errRawCredentialExposure refuses a command that would hand a raw provider
// secret to something outside keylatchd's control. The message does not name
// the opt-out: its reader may be the agent the check exists to stop.
var errRawCredentialExposure = errors.New(
	"keylatch: this command exposes a raw credential value and raw credential access is disabled — refusing to proceed (fail closed); see the Keylatch security docs")

// RequireRawCredentialOptIn gates the two entry points that expose a raw
// provider credential: `keylatch get` and `keylatch run` in a raw-credential
// runtime mode (runtime.IsRawCredentialMode). Gateway and proxy modes pass
// rawCredentialExposure=false and are never gated: their child receives only
// a scoped session token.
//
// Agent detection plays no part: an agent can hide every signal, so neither
// a missing signal nor a session ticket can allow a raw-exposure path. Only
// the operator's allow_unverified_session config field can.
func RequireRawCredentialOptIn(rawCredentialExposure, configAllowsRawCredentials bool) error {
	if !rawCredentialExposure || configAllowsRawCredentials {
		return nil
	}
	return errRawCredentialExposure
}

// configAllowsUnverifiedSession reports whether config.json sets
// allow_unverified_session. Any load error counts as not set.
func configAllowsUnverifiedSession(env llmcontext.Lookup) bool {
	cfg, err := config.Load(paths.Config(env))
	if err != nil {
		return false
	}
	return cfg.AllowUnverifiedSession
}
