package control

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/runner"
)

const gitCredentialVerb = "git-credential" //nolint:gosec // G101: a verb name, not a credential

// runGitCredential is the git credential helper. For a request toward a host
// the session's connection binds, it answers with the placeholder for that
// connection's credential; for anything else it answers nothing. It never has
// the real value to give: the daemon's proxy substitutes it in flight.
func runGitCredential(lookup llmcontext.Lookup, args []string, streams IO) int {
	if len(args) != 1 || args[0] != "get" {
		return 0
	}
	fields := map[string]string{}
	sc := bufio.NewScanner(streams.In)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			fields[k] = v
		}
	}
	session := lookup(runner.ProxySessionVar)
	if session == "" || fields["host"] == "" {
		return 0
	}
	client, err := NewClient(lookup)
	if err != nil {
		return 0
	}
	cred, err := client.Credential(session, CredentialRequest{Protocol: fields["protocol"], Host: fields["host"]})
	if err != nil || cred == nil {
		return 0
	}
	fmt.Fprintf(streams.Out, "username=%s\npassword=%s\n", cred.Username, cred.Password)
	return 0
}
