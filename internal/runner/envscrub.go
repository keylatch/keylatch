package runner

import "strings"

// scrubbedEnvNames are the variables that authenticate to a secret backend.
// A child process never sees them, whatever the parent exported.
var scrubbedEnvNames = map[string]struct{}{
	"BW_SESSION": {}, "BW_CLIENTSECRET": {}, "BWS_ACCESS_TOKEN": {},
	"OP_SERVICE_ACCOUNT_TOKEN": {}, "OP_CONNECT_TOKEN": {},
	"VAULT_TOKEN": {}, "VAULT_ROLE_ID": {}, "VAULT_SECRET_ID": {},
	"AWS_ACCESS_KEY_ID": {}, "AWS_SECRET_ACCESS_KEY": {}, "AWS_SESSION_TOKEN": {},
	"AZURE_CLIENT_SECRET": {}, "GOOGLE_APPLICATION_CREDENTIALS": {},
	"DOPPLER_TOKEN": {}, "INFISICAL_CLIENT_ID": {}, "INFISICAL_CLIENT_SECRET": {},
}

// scrubbedEnvPrefixes cover families of variables: 1Password session tokens
// (OP_SESSION_<account>) and Keylatch's own configuration.
var scrubbedEnvPrefixes = []string{"OP_SESSION_", "KEYLATCH_"}

// ScrubChildEnv returns env (KEY=value entries) without backend credentials
// and KEYLATCH_* configuration. Drivers apply it to the inherited environment
// before adding what the child is meant to receive.
func ScrubChildEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if scrubbedEnvName(name) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func scrubbedEnvName(name string) bool {
	if _, ok := scrubbedEnvNames[name]; ok {
		return true
	}
	for _, p := range scrubbedEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
