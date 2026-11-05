package runner

import (
	"fmt"

	"github.com/keylatch/keylatch/internal/localonly"
	"github.com/keylatch/keylatch/internal/registry"
)

// LocalOnly carries a connection's class and per-field delivery modes into a
// run. Fields are keyed by secret field name.
type LocalOnly struct {
	Class  localonly.Class
	Fields map[string]localonly.Mode
}

// localOnlyEnv resolves every local-only field of tmpl. It returns the
// KEY=VALUE pairs to inject and the set of secret fields that must not be
// read from the store. Any mode without run-time behaviour is refused.
func localOnlyEnv(tmpl registry.ConnectionTemplate, lo LocalOnly, session *localonly.Session) ([]string, map[string]bool, error) {
	if len(lo.Fields) == 0 {
		return nil, nil, nil
	}
	var env []string
	skip := map[string]bool{}
	for _, rule := range tmpl.InjectionRules {
		mode := lo.Fields[rule.Source]
		if mode == "" {
			continue
		}
		if err := localonly.CheckRun(lo.Class, mode); err != nil {
			return nil, nil, fmt.Errorf("field %q: %w", rule.Source, err)
		}
		v, err := session.Value(rule.Source, localonly.DefaultShape)
		if err != nil {
			return nil, nil, err
		}
		env = append(env, rule.EnvVar+"="+v)
		skip[rule.Source] = true
	}
	return env, skip, nil
}

func mergeEnvPairs(env, pairs []string) []string {
	for _, p := range pairs {
		for i := 0; i < len(p); i++ {
			if p[i] == '=' {
				env = appendOrReplace(env, p[:i], p[i+1:])
				break
			}
		}
	}
	return env
}
