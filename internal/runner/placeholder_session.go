package runner

import (
	"strconv"

	"github.com/keylatch/keylatch/internal/registry"
)

// BinaryPlaceholder stands for the path of the keylatch executable in a
// SessionEnv until the process that starts the child fills it in.
const BinaryPlaceholder = "{keylatch}"

// ProxySessionVar names the placeholder session a credential helper asks the
// daemon about.
const ProxySessionVar = "KEYLATCH_PROXY_SESSION"

// CABundleVars name the variables TLS clients read to find extra trusted
// certificate authorities. A placeholder session points all of them at a
// bundle that adds the session CA to the system roots.
var CABundleVars = []string{
	"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
	"GIT_SSL_CAINFO", "AWS_CA_BUNDLE", "DENO_CERT",
}

var proxyVars = []string{
	"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy",
}

// localNoProxy keeps traffic to the child's own loopback servers off the proxy.
const localNoProxy = "localhost,127.0.0.1,::1"

// PlaceholderSessionEnv returns the child environment changes for a
// placeholder run. Each secret variable the template declares is replaced by
// the placeholder for its field, or removed when the field has none, and
// traffic is pointed at the session proxy. Caller proxy and CA variables are
// replaced, so the child cannot reach a destination that bypasses the session.
func PlaceholderSessionEnv(tmpl registry.ConnectionTemplate, placeholders map[string]string, proxyURL string) SessionEnv {
	env := SessionEnv{}
	env.Strip = append(env.Strip, proxyVars...)
	env.Strip = append(env.Strip, CABundleVars...)
	env.Strip = append(env.Strip, "NODE_USE_ENV_PROXY")
	for _, rule := range tmpl.InjectionRules {
		env.Strip = append(env.Strip, rule.EnvVar)
		if v, ok := placeholders[rule.Source]; ok {
			env.Set = append(env.Set, EnvAssign{rule.EnvVar, v})
		}
	}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		env.Set = append(env.Set, EnvAssign{name, proxyURL})
	}
	return SessionEnv{
		Strip: env.Strip,
		Set: append(env.Set,
			EnvAssign{"NO_PROXY", localNoProxy},
			EnvAssign{"no_proxy", localNoProxy},
			EnvAssign{"NODE_USE_ENV_PROXY", "1"},
			EnvAssign{"KEYLATCH_RUNTIME", "placeholder"},
		),
	}
}

// GitCredentialEnv returns the child environment changes that make git ask
// keylatch for credentials toward the hosts the template's git adapter names.
// Helpers configured elsewhere are reset first, so git never falls back to a
// stored credential, and prompting is disabled.
func GitCredentialEnv(tmpl registry.ConnectionTemplate, sessionID string) []EnvAssign {
	if tmpl.Adapter.Kind != registry.AdapterGitCredential {
		return nil
	}
	set := []EnvAssign{
		{"GIT_CONFIG_COUNT", strconv.Itoa(1 + len(tmpl.Adapter.Hosts))},
		{"GIT_CONFIG_KEY_0", "credential.helper"},
		{"GIT_CONFIG_VALUE_0", ""},
		{"GIT_TERMINAL_PROMPT", "0"},
		{ProxySessionVar, sessionID},
	}
	for i, host := range tmpl.Adapter.Hosts {
		n := strconv.Itoa(i + 1)
		set = append(set,
			EnvAssign{"GIT_CONFIG_KEY_" + n, "credential.https://" + host + ".helper"},
			EnvAssign{"GIT_CONFIG_VALUE_" + n, "!" + BinaryPlaceholder + " git-credential"},
		)
	}
	return set
}
