package cli

import (
	"errors"
	"os/user"

	"github.com/keylatch/keylatch/internal/config"
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

// operatorHome returns the home directory of the account running keylatch
// from the user database rather than $HOME, which the caller controls.
// Replaced in tests.
var operatorHome = func() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if u.HomeDir == "" {
		return "", errors.New("no home directory for the current user")
	}
	return u.HomeDir, nil
}

// configAllowsUnverifiedSession reports whether the operator's config.json
// sets allow_unverified_session. Only the default config path counts: the
// KEYLATCH_CONFIG, KEYLATCH_CONFIG_DIR and XDG_CONFIG_HOME overrides are
// ignored, and the file must belong to the current user and not be writable
// by group or others. Anything else counts as not set.
func configAllowsUnverifiedSession() bool {
	home, err := operatorHome()
	if err != nil {
		return false
	}
	path := paths.DefaultConfig(home)
	data, err := readOperatorFile(path)
	if err != nil {
		return false
	}
	cfg, err := config.LoadBytes(path, data)
	if err != nil {
		return false
	}
	return cfg.AllowUnverifiedSession
}
