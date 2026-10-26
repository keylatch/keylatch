package cli

import (
	"github.com/keylatch/keylatch/internal/audit"
	"github.com/spf13/cobra"
)

func newKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "key <sign|verify|encrypt|decrypt|jwt-sign|allow|revoke|list|agent> [<connection>] [flags]",
		Short: "Sign, verify, encrypt or decrypt with a key that never leaves the daemon",
		Long: `Run a cryptographic operation with a connection's key. The daemon reads the
key, performs the operation and returns only the result; the key is never
delivered to this process, its output or the audit log.

  keylatch key sign <connection> [--field <name>] [--alg <alg>] [--in <file|->] [--encoding raw|hex|base64]
  keylatch key verify <connection> --sig <file> [--in <file|->]
  keylatch key encrypt <connection> [--aad <text>] [--in <file|->]
  keylatch key decrypt <connection> [--aad <text>] [--in <file|->]
  keylatch key jwt-sign <connection> [--alg HS256|ES256|EdDSA] [--kid <id>] [--in <claims.json|->]
  keylatch key allow <connection> --field <name> [--secret <backend path>] [--op <ops>] [--alg <algs>] [--agent-decrypt] [--ssh-agent] [--host-key <fingerprint>]
  keylatch key revoke <connection> [--field <name>] [--op <ops>] [--alg <algs>] [--agent-decrypt] [--ssh-agent]
  keylatch key list [<connection>]
  keylatch key agent --protocol ssh|gpg --socket <path>

Algorithms: HS256, HS384, HS512, EdDSA (Ed25519), ES256, ES384, PS256, RS256,
A256GCM. A connection allows only the operations and algorithms its allowlist
names; 'allow' adds or widens an entry and is refused for agent and host
callers, 'revoke' narrows or removes one and is open to any caller. Input comes from stdin or --in; the result goes to stdout or --out.
Key operations need a running system broker or 'keylatchd serve'. On Unix,
'agent' exposes an owner-only protocol socket and relays signing requests to
the daemon. Keys stay in the daemon; stop the relay with Ctrl-C.`,
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE: func(*cobra.Command, []string) error {
			return NewBackendUnavailable("key operations run in the keylatch daemon: start it with 'keylatchd serve'")
		},
	}
}

// OpenAuditEmitter opens the audit log for a long-running process. The cleanup
// function closes the log and zeroes its key.
func OpenAuditEmitter() (audit.Emitter, func(), error) {
	l, cleanup, err := OpenAuditLogger()
	if err != nil {
		return nil, nil, err
	}
	return audit.AsEmitter(l), cleanup, nil
}
