package proxy

import "strings"

// caEnvVars are the environment variable names that point to the CA cert file.
var caEnvVars = []string{
	"SSL_CERT_FILE",
	"REQUESTS_CA_BUNDLE",
	"NODE_EXTRA_CA_CERTS",
	"GIT_SSL_CAINFO",
}

// InjectCAEnv injects SSL_CERT_FILE, REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS,
// and GIT_SSL_CAINFO into env, pointing each to caCertPath.
//
// When inject is false, env is returned unmodified.
// Existing conflicting values are overridden (not duplicated).
func InjectCAEnv(env []string, caCertPath string, inject bool) []string {
	if !inject {
		return env
	}

	// Build a copy of env, removing any existing CA env vars.
	result := make([]string, 0, len(env)+len(caEnvVars))
	for _, entry := range env {
		if !isCAEnvEntry(entry) {
			result = append(result, entry)
		}
	}

	// Append updated values.
	for _, name := range caEnvVars {
		result = append(result, name+"="+caCertPath)
	}
	return result
}

// isCAEnvEntry returns true if entry is one of the CA env var assignments.
func isCAEnvEntry(entry string) bool {
	for _, name := range caEnvVars {
		if strings.HasPrefix(entry, name+"=") {
			return true
		}
	}
	return false
}
