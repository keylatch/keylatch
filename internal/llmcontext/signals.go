package llmcontext

import "github.com/keylatch/keylatch/internal/harness"

// Signal is one environment variable that marks an agent session.
type Signal struct {
	EnvKey  string
	Match   harness.Match
	Label   string // returned by Reasons; the variable name, never its value
	Harness string // harness ID, or "" for a manual label
}

// Signals lists every environment signal, derived from the harness table.
var Signals = func() []Signal {
	owned := harness.Signals()
	out := make([]Signal, 0, len(owned))
	for _, s := range owned {
		out = append(out, Signal{EnvKey: s.Name, Match: s.Match, Label: s.Name, Harness: s.Harness})
	}
	return out
}()
