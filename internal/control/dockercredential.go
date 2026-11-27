package control

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/runner"
)

const dockerCredentialVerb = "docker-credential" //nolint:gosec // G101: a verb name, not a credential

// notFound is the message the Docker credential protocol uses for a server it
// has no credentials for.
const notFound = "credentials not found in native keychain"

// RunDockerCredential is docker-credential-keylatch, the helper behind
// `"credsStore": "keylatch"`. Like the git helper it answers only for a
// registry the session's connection binds, and what it answers with is the
// placeholder for that connection's credential, never the real value: the
// daemon's proxy substitutes it when the registry request goes out. store and
// erase do nothing, because Keylatch is the only place credentials live.
func RunDockerCredential(lookup llmcontext.Lookup, args []string, streams IO) int {
	if len(args) != 1 {
		fmt.Fprintln(streams.ErrOut, "usage: docker-credential-keylatch get|store|erase|list")
		return 1
	}
	switch args[0] {
	case "store", "erase":
		drain(streams)
		return 0
	case "list":
		fmt.Fprintln(streams.Out, "{}")
		return 0
	case "get":
	default:
		fmt.Fprintf(streams.ErrOut, "docker-credential-keylatch: unknown command %q\n", args[0])
		return 1
	}

	line, _ := bufio.NewReader(streams.In).ReadString('\n')
	serverURL := strings.TrimSpace(line)
	host := registryHost(serverURL)
	session := lookup(runner.ProxySessionVar)
	if session == "" || host == "" {
		fmt.Fprintln(streams.Out, notFound)
		return 1
	}
	client, err := NewClient(lookup)
	if err != nil {
		fmt.Fprintln(streams.Out, notFound)
		return 1
	}
	cred, err := client.Credential(session, CredentialRequest{Protocol: "https", Host: host})
	if err != nil || cred == nil {
		fmt.Fprintln(streams.Out, notFound)
		return 1
	}
	out, _ := json.Marshal(map[string]string{"ServerURL": serverURL, "Username": cred.Username, "Secret": cred.Password})
	fmt.Fprintln(streams.Out, string(out))
	return 0
}

func drain(streams IO) {
	sc := bufio.NewScanner(streams.In)
	for sc.Scan() {
	}
}

// registryHost reduces the server URL Docker passes (ghcr.io,
// https://index.docker.io/v1/) to its host and port.
func registryHost(serverURL string) string {
	if serverURL == "" {
		return ""
	}
	if !strings.Contains(serverURL, "://") {
		serverURL = "https://" + serverURL
	}
	u, err := url.Parse(serverURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}
