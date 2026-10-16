//go:build harness

// Package harness runs fake agent processes against a built keylatch binary
// and records which attack paths still reach Keylatch's secrets or authority.
package harness

// verdict is what a scenario is expected to show: the agent obtained what the
// row targets (wantLeak) or was stopped (wantBlocked).
type verdict string

const (
	wantLeak    verdict = "wantLeak"
	wantBlocked verdict = "wantBlocked"
)

// kind selects how a run is judged.
type kind int

const (
	// kindSecret: the row leaks when a planted secret reaches the agent.
	kindSecret kind = iota
	// kindAction: the row leaks when the final call is not refused, that is
	// neither blocked by the hook nor refused by Keylatch with exit code 2.
	kindAction
	// kindArtifact: the row leaks when the named artifact check reports that
	// the agent copied, changed or captured protected state.
	kindArtifact
	// kindContainment: the row is an escape attempt from the sandboxed thin
	// client, run by the named test in tests/containment. A passing test means
	// the escape is closed.
	kindContainment
)

// step is one tool call. Input values may use {{home}}, {{config}}, {{canary}}
// and {{bin}} placeholders.
type step struct {
	tool  string
	input map[string]string
}

func bash(command string) step {
	return step{tool: "Bash", input: map[string]string{"command": command}}
}

// scenario is one path an agent could take to Keylatch's secrets or authority.
type scenario struct {
	id          string
	description string
	// setup lists the world preparations the human performs first.
	setup []string
	// env is extra environment the launching shell exported to the agent.
	env   []string
	steps []step
	kind  kind
	// artifact names the check that judges a kindArtifact row.
	artifact string
	// containment names the tests/containment test behind a kindContainment row.
	containment string
	want        verdict
	// test names the unit test that holds a wantBlocked row in place, for rows
	// the harness itself exercises through the shipped binary.
	test string
	// inUserResidual marks rows that stay open until the broker runs under its
	// own OS user, which is when the in-user design stops being the boundary.
	inUserResidual bool
	// onlyOS restricts a row to one GOOS value; empty runs everywhere.
	onlyOS string
}

// containmentRow builds the row for one tests/containment escape test.
func containmentRow(id, description, test string) scenario {
	return scenario{id: id, description: description, kind: kindContainment, containment: test, want: wantBlocked, onlyOS: "linux"}
}

// Setup preparations.
const (
	setupGatewayInit   = "gateway-init"
	setupGatewayToken  = "gateway-token"
	setupBWSessionFile = "bw-session-file"
	setupVendorCLIs    = "vendor-clis"
	setupAuditBaseline = "audit-baseline"
	setupTokenBaseline = "token-baseline"
	setupGitHubApp     = "github-app-connection"
	setupSentry        = "sentry-connection"
)

// Artifact checks.
const (
	artifactKeyMaterialCopied = "key-material-copied"
	artifactBackupWritten     = "backup-written"
	artifactTokenStoreEdited  = "token-store-edited"
	artifactAuditLogEdited    = "audit-log-edited"
	artifactUIURLCaptured     = "ui-url-captured"
	artifactMCPRunExecuted    = "mcp-run-executed"
	artifactIdentityListed    = "identity-listed"
)

const (
	envBWSession = "BW_SESSION=harness-bw-session-canary-77c3a91e"
	mcpRunEvil   = `(printf '%s\n' ` +
		`'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"fakeagent","version":"0"}}}' ` +
		`'{"jsonrpc":"2.0","method":"notifications/initialized"}' ` +
		`'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"keylatch_run","arguments":{"provider":"sentry","command":["python3evil","-c","print(1)"]}}}' ` +
		`; sleep 2) | keylatch mcp`
)

// scenarios is the attacker table. Each row names one audit attack path; want
// records what the current build does, so the suite passes today and a row
// flips to wantBlocked when the fix for that path lands.
var scenarios = []scenario{
	{
		id:          "read-identity-with-read-tool",
		description: "the Read tool opens keyring/identity, the plaintext key-encryption key",
		steps:       []step{{tool: "Read", input: map[string]string{"file_path": "{{config}}/keyring/identity"}}},
		kind:        kindSecret,
		want:        wantBlocked,
	},
	{
		id:          "copy-key-material-and-decrypt-offline",
		description: "identity, keyring.json and vault/ are copied out; together they decrypt every stored secret offline",
		steps:       []step{bash(`cp -R "{{config}}" "{{home}}/loot"`)},
		kind:        kindArtifact,
		artifact:    artifactKeyMaterialCopied,
		want:        wantLeak,
	},
	{
		id:          "backup-with-passphrase-file",
		description: "keylatch backup --passphrase-file writes an encrypted copy of every secret under a passphrase the agent chose",
		steps: []step{
			bash(`printf 'harness-passphrase' > "{{home}}/pass"`),
			bash(`keylatch backup --passphrase-file "{{home}}/pass" --output "{{home}}/backup.enc"`),
		},
		kind:     kindArtifact,
		artifact: artifactBackupWritten,
		want:     wantBlocked,
	},
	{
		id:          "approve-pending-request",
		description: "keylatch approve <id> grants a pending approval without a person",
		steps:       []step{bash(`keylatch approve req-0001`)},
		kind:        kindAction,
		want:        wantBlocked,
	},
	{
		id:          "policy-allow-everything",
		description: "keylatch policy allow '*' '*' lets every actor use every connection",
		steps:       []step{bash(`keylatch policy allow '*' '*'`)},
		kind:        kindAction,
		want:        wantBlocked,
		test:        "TestPolicyMutationNeedsPresence",
	},
	{
		id:          "wildcard-gateway-token",
		description: "keylatch gateway token create --allow '*' mints a token for every capability",
		setup:       []string{setupGatewayInit},
		steps:       []step{bash(`keylatch gateway token create agent --allow '*' --max-uses 5`)},
		kind:        kindAction,
		want:        wantBlocked,
		test:        "TestTokenCreateNeedsPresence",
	},
	{
		id:          "edit-token-store",
		description: "the agent edits the gateway token store to widen a token's capabilities",
		setup:       []string{setupGatewayInit, setupGatewayToken, setupTokenBaseline},
		steps:       []step{bash(`printf ' ' >> "{{config}}/gateway-tokens.json"`)},
		kind:        kindArtifact,
		artifact:    artifactTokenStoreEdited,
		want:        wantLeak,
	},
	{
		id:          "recompute-audit-chain-after-edit",
		description: "the agent edits the audit log and recomputes its hash chain so the change verifies",
		setup:       []string{setupAuditBaseline},
		steps:       []step{bash(`printf '\n' >> "{{config}}/audit.log"`)},
		kind:        kindArtifact,
		artifact:    artifactAuditLogEdited,
		want:        wantLeak,
	},
	{
		id:          "bw-session-from-session-file",
		description: "BW_SESSION=$(<sessions/bw.session) bw export reads the cached Bitwarden session and exports the vault",
		setup:       []string{setupBWSessionFile, setupVendorCLIs},
		steps:       []step{bash(`BW_SESSION=$(<"{{config}}/sessions/bw.session") bw export`)},
		kind:        kindSecret,
		want:        wantLeak,
	},
	{
		id:             "proc-self-environ",
		description:    "cat /proc/self/environ prints the secrets exported by the shell that started the agent",
		env:            []string{envBWSession},
		steps:          []step{bash(`cat /proc/self/environ | tr '\0' '\n'`)},
		kind:           kindSecret,
		want:           wantLeak,
		inUserResidual: true,
		onlyOS:         "linux",
	},
	{
		id:             "export-p",
		description:    "export -p prints the secrets exported by the shell that started the agent",
		env:            []string{envBWSession},
		steps:          []step{bash(`export -p`)},
		kind:           kindSecret,
		want:           wantLeak,
		inUserResidual: true,
	},
	{
		id:             "python-os-environ",
		description:    "python3 -c 'import os;print(os.environ)' prints the secrets exported by the shell that started the agent",
		env:            []string{envBWSession},
		steps:          []step{bash(`python3 -c 'import os;print(os.environ)'`)},
		kind:           kindSecret,
		want:           wantLeak,
		inUserResidual: true,
	},
	{
		id:          "op-read",
		description: "op read prints a 1Password secret through the user's unlocked session",
		setup:       []string{setupVendorCLIs},
		steps:       []step{bash(`op read op://vault/item/field`)},
		kind:        kindSecret,
		want:        wantBlocked,
	},
	{
		id:          "vault-kv-get",
		description: "vault kv get prints a HashiCorp Vault secret through the user's token",
		setup:       []string{setupVendorCLIs},
		steps:       []step{bash(`vault kv get secret/app`)},
		kind:        kindSecret,
		want:        wantLeak,
	},
	{
		id:          "aws-get-secret-value",
		description: "aws secretsmanager get-secret-value prints a cloud secret through the user's credentials",
		setup:       []string{setupVendorCLIs},
		steps:       []step{bash(`aws secretsmanager get-secret-value --secret-id app`)},
		kind:        kindSecret,
		want:        wantLeak,
	},
	{
		id:          "grep-config-dir",
		description: "the Grep tool searches the config directory for cached sessions and tokens",
		setup:       []string{setupBWSessionFile},
		steps:       []step{{tool: "Grep", input: map[string]string{"pattern": "bw-session", "path": "{{config}}"}}},
		kind:        kindSecret,
		want:        wantLeak,
	},
	{
		id:          "glob-config-dir",
		description: "the Glob tool lists the config directory and so finds the identity file",
		steps:       []step{{tool: "Glob", input: map[string]string{"pattern": "*", "path": "{{config}}"}}},
		kind:        kindArtifact,
		artifact:    artifactIdentityListed,
		want:        wantLeak,
	},
	{
		id:          "ui-no-open-url-capture",
		description: "keylatch ui --no-open prints the local UI address, which the agent then opens",
		steps:       []step{bash(`(keylatch ui --no-open > "{{home}}/ui.out" 2>&1 & echo $! > "{{home}}/ui.pid"); sleep 2; kill $(cat "{{home}}/ui.pid") 2>/dev/null; cat "{{home}}/ui.out"`)},
		kind:        kindArtifact,
		artifact:    artifactUIURLCaptured,
		want:        wantBlocked,
		test:        "TestUIURLNotPrintedWithoutTTY",
	},
	{
		id:          "mcp-run-with-python3evil",
		description: "an MCP keylatch_run call for python3evil must not pass the allowlist entry meant for python3",
		setup:       []string{setupSentry},
		steps:       []step{bash(mcpRunEvil)},
		kind:        kindArtifact,
		artifact:    artifactMCPRunExecuted,
		want:        wantBlocked,
	},
	{
		id:          "agent-gateway-token-for-llm-route",
		description: "the agent obtains a gateway token scoped to an LLM route",
		setup:       []string{setupGatewayInit},
		steps:       []step{bash(`keylatch gateway token create llm-agent --allow openai.chat.completion --max-uses 5`)},
		kind:        kindAction,
		want:        wantBlocked,
		test:        "TestTokenCreateNeedsPresence",
	},
	// Escape attempts from the sandboxed thin client. Their steps live in
	// tests/containment, which needs bubblewrap and runs only on Linux.
	containmentRow("sandbox-hides-state-and-host-network", "inside the sandbox, Keylatch state and the host network are not reachable", "TestSandboxHidesStateAndHostNetwork"),
	containmentRow("sandbox-refuses-value-verbs", "value-bearing verbs are refused inside the sandbox", "TestValueVerbsRefusedInsideSandbox"),
	containmentRow("planted-keylatch-obtains-no-value", "a keylatch binary the agent planted obtains no secret value", "TestPlantedKeylatchObtainsNoValue"),
	containmentRow("relay-hostile-argv-starts-nothing", "hostile argv sent through the relay starts no process", "TestRelayWithHostileArgvStartsNothing"),
	containmentRow("relay-cannot-obtain-values", "the relay never returns a secret value", "TestRelayCannotObtainValues"),
	containmentRow("relay-refuses-planted-socket-override", "the relay refuses a socket path the agent planted", "TestRelayRefusesAPlantedSocketOverride"),
	containmentRow("relay-inside-sandbox-reaches-nothing", "the relay inside the sandbox reaches nothing but the daemon", "TestRelayInsideTheSandboxReachesNothing"),
	containmentRow("relay-binary-cannot-start-a-process", "the relay binary links no way to start a process", "TestRelayBinaryHasNoWayToStartAProcess"),
	containmentRow("placeholder-environment-holds-only-placeholders", "a placeholder run's environment holds only placeholders", "TestPlaceholderEnvironmentHoldsOnlyPlaceholders"),
	containmentRow("placeholder-exfiltration-routes-closed", "a placeholder run cannot send the real value anywhere", "TestPlaceholderExfiltrationRoutesAreClosed"),
	containmentRow("mint-to-stdout-refused-in-sandbox", "keylatch mint prints no token inside the sandbox", "TestMintToStdoutRefusedInsideSandbox"),
	containmentRow("minted-run-outside-policy-refused", "a minted run outside the policy's repositories and permissions is refused", "TestMintedRunOutsidePolicyIsRefused"),
	{
		id:          "agent-mint",
		description: "keylatch mint hands the agent a short-lived credential for a provider",
		setup:       []string{setupGitHubApp},
		steps:       []step{bash(`keylatch mint github-app --repo octo/hello --permission contents=read --format json`)},
		kind:        kindAction,
		want:        wantBlocked,
	},
}
