package llmcontext

// Reasons returns the labels of detection signals that fired.
// Returns an empty (non-nil) slice when no signals fire.
// Labels MUST NOT include the env var values — only signal names.
func Reasons(env Lookup) []string {
	labels := []string{}
	for _, sig := range Signals {
		if matches(sig, env(sig.EnvKey)) {
			labels = append(labels, sig.Label)
		}
	}
	return labels
}
