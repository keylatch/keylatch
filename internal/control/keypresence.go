package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/keylatch/keylatch/internal/presence"
)

// allowedEntry is the part of a listed allowlist entry a human compares.
type allowedEntry struct {
	Operations   []string `json:"operations"`
	Algorithms   []string `json:"algorithms"`
	AgentDecrypt bool     `json:"agent_decrypt"`
	SSHAgent     *struct {
		HostKeys []string `json:"host_keys"`
	} `json:"ssh_agent"`
}

// keyAllowSummary is what the human approves when an allowlist entry is added
// or widened: the entry before and the additions this request makes.
func keyAllowSummary(kp KeyPolicyRequest, before *allowedEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "allow key operations on %s field %s\n", kp.Connection, kp.Field)
	state := "new entry"
	if before != nil {
		hosts := 0
		if before.SSHAgent != nil {
			hosts = len(before.SSHAgent.HostKeys)
		}
		state = fmt.Sprintf("operations %s; algorithms %s; agent decrypt %t; ssh-agent host keys %d",
			listOrNone(before.Operations), listOrNone(before.Algorithms), before.AgentDecrypt, hosts)
	}
	fmt.Fprintf(&b, "  before:   %s\n", state)
	fmt.Fprintf(&b, "  adds:     operations %s; algorithms %s\n", listOrNone(kp.Operations), listOrNone(kp.Algorithms))
	fmt.Fprintf(&b, "  agent decrypt: %t; ssh-agent: %t; host keys %s\n", kp.AgentDecrypt, kp.SSHAgent, listOrNone(kp.HostKeys))
	fmt.Fprintf(&b, "  secret:   %s", orDefault(kp.Secret, "unchanged"))
	return b.String()
}

func listOrNone(in []string) string {
	if len(in) == 0 {
		return "none"
	}
	return strings.Join(slices.Sorted(slices.Values(in)), ",")
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// requireAllowPresence asks a human to approve widening the allowlist,
// bound to the entry as it stands now. An entry that cannot be read is
// shown as unknown rather than skipped, so the prompt never hides a change.
func requireAllowPresence(c *Client, kp KeyPolicyRequest) (presence.Proof, error) {
	var before *allowedEntry
	if resp, err := c.KeyPolicy(KeyPolicyRequest{Action: "list", Connection: kp.Connection}); err == nil && resp.OK {
		var doc map[string]map[string]allowedEntry
		if json.Unmarshal(resp.Stdout, &doc) == nil {
			if e, ok := doc[kp.Connection][kp.Field]; ok {
				before = &e
			}
		}
	}
	proof, err := presence.Require(context.Background(), presence.ActionKeyAllow, keyAllowSummary(kp, before))
	switch {
	case err == nil:
		return proof, nil
	case errors.Is(err, presence.ErrNoTTY):
		return proof, errors.New("changing the allowlist needs a human at an interactive terminal; it cannot be scripted, piped or run by an agent")
	case errors.Is(err, presence.ErrAgentTerminal):
		return proof, errors.New("changing the allowlist needs a human; this terminal belongs to an agent session")
	case errors.Is(err, presence.ErrDenied):
		return proof, errors.New("the allowlist change was not approved")
	}
	return proof, fmt.Errorf("the allowlist change could not be approved: %w", err)
}
