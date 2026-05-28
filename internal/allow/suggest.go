// Package allow suggests provider allowlists from local agent environment.
package allow

import (
	"encoding/json"
	"os"
)

// envVarRules maps known provider env vars to provider names.
var envVarRules = []struct{ EnvVar, Provider string }{
	{"OPENAI_API_KEY", "openai"},
	{"ANTHROPIC_API_KEY", "anthropic"},
	{"GITHUB_TOKEN", "github"},
	{"STRIPE_SECRET_KEY", "stripe"},
	{"SLACK_BOT_TOKEN", "slack"},
	{"OPENROUTER_API_KEY", "openrouter"},
	{"GOOGLE_API_KEY", "google"},
	{"AZURE_OPENAI_API_KEY", "azure-openai"},
	{"COHERE_API_KEY", "cohere"},
	{"MISTRAL_API_KEY", "mistral"},
	{"GEMINI_API_KEY", "gemini"},
	{"HUGGINGFACE_TOKEN", "huggingface"},
	{"REPLICATE_API_TOKEN", "replicate"},
	{"ELEVENLABS_API_KEY", "elevenlabs"},
	{"CLOUDFLARE_API_TOKEN", "cloudflare"},
	{"SUPABASE_SERVICE_ROLE_KEY", "supabase-service-role"},
	{"TURSO_AUTH_TOKEN", "turso"},
	{"PINECONE_API_KEY", "pinecone"},
	{"WEAVIATE_API_KEY", "weaviate"},
	{"RESEND_API_KEY", "resend"},
	{"SENDGRID_API_KEY", "sendgrid"},
}

// Suggest returns a list of provider names that appear likely given the current
// environment and agent config files. Conservative: requires at least 2 signals
// (env var present AND provider found in agent config) to avoid false positives.
// If fewer than 2 signals are available for any provider, the env-var alone is
// sufficient if the var is non-empty (single-signal mode for short lists).
func Suggest(agentConfigPath string) []string {
	// Signal 1: env vars present.
	envMatches := map[string]bool{}
	for _, rule := range envVarRules {
		if v := os.Getenv(rule.EnvVar); v != "" {
			envMatches[rule.Provider] = true
		}
	}

	// Signal 2: provider mentioned in agent config file (e.g. ~/.claude/settings.json).
	configMatches := map[string]bool{}
	if agentConfigPath != "" {
		if data, err := os.ReadFile(agentConfigPath); err == nil {
			var cfg map[string]interface{}
			if json.Unmarshal(data, &cfg) == nil {
				raw, _ := json.Marshal(cfg)
				content := string(raw)
				for _, rule := range envVarRules {
					if contains(content, rule.Provider) {
						configMatches[rule.Provider] = true
					}
				}
			}
		}
	}

	// Build suggestions: prefer 2-signal matches; include 1-signal if total < 3.
	var both, envOnly []string
	for p := range envMatches {
		if configMatches[p] {
			both = append(both, p)
		} else {
			envOnly = append(envOnly, p)
		}
	}
	if len(both) > 0 {
		return dedup(both)
	}
	return dedup(envOnly)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && stringContains(s, sub))
}

func stringContains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func dedup(ss []string) []string {
	seen := map[string]bool{}
	out := ss[:0]
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
