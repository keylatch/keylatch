package control

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/harness"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/policy/connpolicy"
	"github.com/keylatch/keylatch/internal/policy/enforce"
)

// needsApproval says whether a run must be approved before it starts. The
// policy's answer decides; a policy that gave none leaves constrained callers
// needing one.
func needsApproval(approval string, kind Kind) bool {
	switch approval {
	case connpolicy.ApprovalAsk, connpolicy.ApprovalPresence:
		return true
	case connpolicy.ApprovalAuto:
		return false
	}
	return kind.Constrained()
}

// gateTier asks the policy engine whether the caller may use the tier for this
// request. A daemon without an engine serves D2 and D3 as before and refuses
// anything that must be decided (required).
func (s *Server) gateTier(ctx context.Context, kind Kind, rr *RunRequest, tier Tier, required bool) (enforce.Decision, *refusal) {
	if s.cfg.Decide == nil {
		if required {
			return enforce.Decision{}, &refusal{CodeRefused, exitcode.PolicyDeny, fmt.Sprintf("tier %s needs a policy engine and this daemon has none", tier)}
		}
		return enforce.Decision{Allow: true}, nil
	}
	runtime := rr.Runtime
	switch tier {
	case TierContained:
		runtime = containedRuntime
	case TierAdapter:
		runtime = adapterRuntime
	}
	dec := s.cfg.Decide(ctx, enforce.Request{
		Connection: rr.Connection, Runtime: runtime, Caller: kind,
		Command: rr.Command, CWD: rr.CWD, Tier: string(tier),
	})
	if !dec.Allow {
		return dec, &refusal{CodeRefused, exitcode.PolicyDeny, fmt.Sprintf("policy denies %s: %s", tier, dec.Reason)}
	}
	return dec, nil
}

// approveSession collects the approval a D2 or D3 request needs.
func (s *Server) approveSession(ctx context.Context, kind Kind, rr *RunRequest, tier Tier, dec enforce.Decision) *refusal {
	if s.cfg.Approve == nil {
		return &refusal{CodeRefused, exitcode.ApprovalRequired, fmt.Sprintf("tier %s needs an approval for %s callers and this daemon cannot collect one", tier, kind)}
	}
	req := ApprovalRequest{
		Connection: rr.Connection, Tier: tier, Argv: rr.Command, Hosts: dec.Hosts, TTL: dec.MaxTTL, Caller: kind, Project: rr.CWD,
		Plan: fmt.Sprintf("run %s with %s access to %s", strings.Join(rr.Command, " "), tier, rr.Connection),
	}
	if _, err := s.cfg.Approve(ctx, req); err != nil {
		return &refusal{CodeRefused, exitcode.ApprovalRequired, "approval refused: " + err.Error()}
	}
	return nil
}

// pathVars are the values of the ${variables} a policy's paths may use for a
// run in project.
func (s *Server) pathVars(project string) map[string][]string {
	home, _ := os.UserHomeDir()
	vars := map[string][]string{
		"project":        {project},
		"keylatch_state": {paths.ConfigDir(s.cfg.Env)},
	}
	if cc := s.cfg.Contained; cc != nil {
		vars["toolchain_caches"] = cc.ReadOnly
	}
	if home != "" {
		for _, p := range []string{".mozilla", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware"} {
			vars["browser_profiles"] = append(vars["browser_profiles"], filepath.Join(home, p))
		}
		for _, p := range harness.ConfigDirNames() {
			vars["harness_config"] = append(vars["harness_config"], filepath.Join(home, p))
		}
	}
	return vars
}

// expandPaths turns a policy's paths into absolute ones: ${name} becomes each
// of its values, ~/ the daemon user's home. A path that cannot be expanded is
// dropped.
func expandPaths(list []string, vars map[string][]string) []string {
	home, _ := os.UserHomeDir()
	var out []string
	for _, p := range list {
		switch {
		case strings.HasPrefix(p, "${"):
			name, rest, ok := strings.Cut(strings.TrimPrefix(p, "${"), "}")
			if !ok {
				continue
			}
			for _, v := range vars[name] {
				out = append(out, filepath.Join(v, rest))
			}
		case p == "~" || strings.HasPrefix(p, "~/"):
			if home != "" {
				out = append(out, filepath.Join(home, strings.TrimPrefix(p, "~")))
			}
		case filepath.IsAbs(p):
			out = append(out, filepath.Clean(p))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
