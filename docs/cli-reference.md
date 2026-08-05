# Keylatch CLI Reference

## Global flags

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format |
| `--quiet` | Suppress non-essential output |
| `--log-level` | Set log verbosity (`debug`, `info`, `warn`, `error`) |
| `--version` | Print version information and exit (equivalent to the `keylatch version` subcommand below) |

## Exit codes

| Code | Name | Meaning |
|------|------|---------|
| `0` | OK | Command succeeded |
| `1` | UserError | Invalid input or user configuration error |
| `2` | SecurityBlock | Command blocked by LLM-session guard |
| `3` | Missing | Requested resource not found |
| `4` | BackendUnavailable | Credential backend is not reachable |
| `5` | OperationFailed | Internal or unrecoverable error |

---

## Runtime modes

The `--runtime` flag is used with `keylatch run`.

| Mode | LLM sessions | Description |
|------|-------------|-------------|
| `gateway_typed` | Allowed | Default. Credential injected via local typed gateway with schema validation. |
| `gateway_sdk` | Allowed | SDK-compatible credential exchange through the gateway. |
| `direct_brokered` | Allowed | Direct injection via trusted broker process. |
| `gateway_proxy` | Allowed | Credential proxy through the local gateway. |

All four modes are permitted in LLM sessions. Raw credential values are never returned to the agent process in any mode. `keylatch get` is always blocked in LLM sessions (exit 2, SecurityBlock).

---

## Commands

### `keylatch setup`

Guided first-time setup wizard.

```
keylatch setup
```

Interactive wizard that selects a backend, initializes `~/.keylatch/`, stores a first credential, and optionally configures an agent profile. Use this on first install.

---

### `keylatch init`

Initialize a Keylatch configuration skeleton or scaffold an integration.

```
keylatch init ci [--write] [--config <path>] [--force]
keylatch init integration --agent <agent>
```

**Subcommands:**

#### `keylatch init ci`

Generate a `keylatch.yaml` skeleton and GitHub Actions workflow snippet.

| Flag | Description |
|------|-------------|
| `--write` | Write the GitHub Actions snippet to `.github/workflows/keylatch-ci.yml` |
| `--config` | Output path for `keylatch.yaml` (default: `./keylatch.yaml`) |
| `--force` | Overwrite existing files |

#### `keylatch init integration`

Scaffold a Keylatch integration for an AI agent in the current project.

```
keylatch init integration --agent <agent>
```

Detects the project language (Go: `go.mod`, Python: `pyproject.toml`/`requirements.txt`, Node: `package.json`) and writes:
- `scripts/keylatch-setup.sh` (shell), `scripts/keylatch_setup.py` (Python), or `scripts/keylatchSetup.ts` (Node)
- `.keylatch/integration.yml` with the detected agent and placeholder provider list

| Flag | Description |
|------|-------------|
| `--agent` | AI agent to integrate with (required). One of: `claude-code`, `gemini`, `windsurf`, `cursor`, `generic` |

**Example:**

```bash
keylatch init integration --agent claude-code
# Writes: .keylatch/integration.yml, scripts/keylatch-setup.sh
# Prints next steps and a link to docs/integration/agents/claude-code.md
```

After running, edit `.keylatch/integration.yml` to set your actual provider name, then run the generated setup script.

---

### `keylatch bootstrap`

Initialize local keylatch configuration (scriptable).

```
keylatch bootstrap [--dry-run] [--json] [--backend <name>]
```

Creates `~/.keylatch/` (mode `0700`), `config.json` (mode `0600`), and `audit.log` (mode `0600`). Idempotent — safe to run multiple times.

| Flag | Description |
|------|-------------|
| `--dry-run` | Print plan without writing anything |
| `--json` | Output plan as JSON |
| `--backend` | Set credential backend (`file`, `keychain`, `op`, `bw`) |

---

### `keylatch doctor`

Diagnose keylatch configuration and environment.

```
keylatch doctor [--json] [--verbose] [--redact-paths] [--category <cats>] [--quiet]
```

**Exit codes:**
- `0` — all checks passed (warnings are informational only)
- `1` — warnings present but no blocking failures
- `2` — at least one check failed (blocking failure)

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON v1 schema (`_schema`, `exit`, `checks`, `summary`) |
| `--verbose` | Show all checks, including passing ones |
| `--redact-paths` | Hash path values in output (for support bundles) |
| `--category` | Comma-separated list of categories to run (e.g. `environment,backends`) |
| `--quiet` | Suppress table output; only exit with the appropriate code |
| `--repair` | Attempt automated repair for checks that have a safe, idempotent fix. Currently supported: `acl.keychain_unlock` only (re-issues the keychain ACL via the same logic as `keylatch keychain-repair-acl`). Every other failing/warning check prints `[no automated repair] <name>: run: <fix hint>` instead — most failure classes (missing bootstrap, wrong backend selected, an external CLI not installed) have no safe automated fix. |
| `--yes` | Skip the interactive per-check confirmation prompt that `--repair` shows before repairing |

**JSON v1 schema (`--json`):**

```json
{
  "_schema": "v1",
  "exit": 0,
  "checks": [
    {"name": "F1 bootstrap.keyring", "section": "environment", "ok": true, "detail": "...", "fix": ""}
  ],
  "summary": {"ok": 5, "warn": 1, "fail": 0}
}
```

**Bootstrap checks (F1/F2):**
- `F1 bootstrap.keyring` — verifies `~/.keylatch/keyring/keyring.json` is present and non-empty
- `F2 bootstrap.config` — verifies `~/.keylatch/config.json` is present and parseable

**Integration check (I3):**
- `I3 integration-markers` — walks cwd for known agent marker files (`.claude/settings.json`, `.windsurf/hooks`, `.cursor/rules`, `AGENTS.md`, `CLAUDE.md`, `.gemini/config.yml`). If markers are found but `.keylatch/integration.yml` is absent, reports `[ok]` with an informational note and a link to the relevant integration guide (visible with `--verbose`/`--json`) — this is a suggestion, not a warning, since having an unrelated agent marker present says nothing about install health. Also passes with `[ok]` if `.keylatch/integration.yml` exists.

**Optional-feature checks (informational, not warnings):** `gateway.running` (gateway not started), `F3 plaintext_retention` (runtime monitor / `keylatch ui` not started), and `connections.configured` (no connections added yet) report `[ok]` with an informational detail rather than `[warn]` when the corresponding optional feature simply hasn't been enabled — none of these force doctor's exit code away from `0`.

**`--repair` scope:** currently repairs `acl.keychain_unlock` only, by re-running `RepairACL`/`RepairItemACLs` (the same operations `keylatch keychain-repair-acl` performs). Every other failing/warning check is reported as `[no automated repair] <name>: run: <fix hint>` rather than repaired.

---

### `keylatch version`

Print version information and exit — identical output to the `--version`
global flag (see [Verify the installation](./installation.md#verify-the-installation)).

```
keylatch version [--json]
```

| Flag | Description |
|------|-------------|
| `--json` | Output `{"Version":..., "Commit":..., "BuildDate":...}` |

---

### `keylatch modes`

List available runtime modes.

```
keylatch modes [--json]
```

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON with `modes` array; each entry includes `name`, `available`, `use_when`, `security_level`, `requires`, `reason`, and `fix` |

The `fix` column is populated for unavailable modes and is empty for available ones.

---

### `keylatch connect`

Register a new credential connection.

```
keylatch connect <provider>                          # interactive prompt
keylatch connect <provider> -f api_key=@-            # read from stdin (CI-safe)
keylatch connect <provider> -f api_key=@prompt       # interactive secure prompt
keylatch connect <provider> --provider-ref api_key=<uri>  # resolve from external store
```

**Examples**

```bash
keylatch connect openrouter
keylatch connect sentry -f auth_token=@-
keylatch connect github --provider-ref token=op://Keylatch/github/token
keylatch connect openrouter --provider-ref api_key=aws-sm://us-east-1/prod/openrouter#api_key
keylatch connect openrouter --provider-ref api_key=hashivault://secret/prod/openrouter#api_key
```

**`--provider-ref` URI schemes**

| Scheme | Provider | Required binary | Example |
|--------|----------|----------------|---------|
| `op://vault/item/field` | 1Password CLI | `op` v2+ | `op://Private/Anthropic/api_key` |
| `aws-sm://region/secret[#key]` | AWS Secrets Manager | `aws` CLI v2+ | `aws-sm://us-east-1/prod/openrouter#api_key` |
| `hashivault://mount/path[#field]` | HashiCorp Vault | `vault` CLI v1.17+ | `hashivault://secret/prod/openrouter#api_key` |

**Deferred resolution (EPIC-10)**: The URI is stored verbatim in the keylatch vault.
The external PM is called at runtime (on each `keylatch run` or gateway request) —
the plaintext is never written to disk. Credential rotation in the upstream PM is
automatically picked up on next use.

**Flags**

| Flag | Description |
|------|-------------|
| `--provider-ref <field>=<uri>` | Store a field as an external reference URI (repeatable). Validation is performed locally — the external PM is not contacted at connect time. |
| `--field <field>=<value>` | Supply a field value directly (incompatible with `--provider-ref` for the same field). |

See [External Store References](./backends/external-references.md) for full documentation.

---

### `keylatch backup`

Export an AEAD-encrypted backup of all enrolled connections (T-12-02).

```
keylatch backup [--output <file>] [--passphrase-file <file>]
```

Writes all enrolled connection credentials to an XChaCha20-Poly1305 encrypted
tar archive protected by a separate backup passphrase. The passphrase is
prompted interactively from the terminal (TTY required) or read from a file.

**Security invariants:**

- Blocked in LLM sessions (exit `2`, `SecurityBlock`). Backup is a value-bearing
  operation that must not be accessible to agent sessions.
- The backup passphrase is independent of the vault KEK — compromise of the
  backup passphrase does not compromise the vault, and vice versa.
- Passphrase is never exposed on the command line. The only safe inputs are a
  TTY prompt or `--passphrase-file`.
- Each credential entry is individually AEAD-sealed with the credential path as
  associated data (AAD), binding ciphertext to its identity.

**Archive structure:**

```
keylatch-backup/header.json          — backup parameters (salt, argon2id config)
keylatch-backup/<sanitized-path>     — XChaCha20-Poly1305 sealed credential
```

The `header.json` entry is not encrypted and contains no secret values. It carries
the Argon2id salt and parameters needed to re-derive the KEK from the passphrase.

**Flags**

| Flag | Description |
|------|-------------|
| `--output <file>` | Output file path (default: `keylatch-backup-<timestamp>.enc` in cwd) |
| `--passphrase-file <file>` | Read backup passphrase from this file instead of a TTY prompt |

**Examples**

```bash
# Interactive (TTY required):
keylatch backup

# Non-interactive (CI / scripted restore workflows):
keylatch backup --output /mnt/secure/backup.enc --passphrase-file /run/secrets/backup-passphrase

# Decrypt and inspect (using openssl or a purpose-built restore tool):
keylatch restore backup.enc --output-dir ./restored-vault
```

**Restore / Decryption**

Backups are self-contained. To decrypt a backup:

1. Read `keylatch-backup/header.json` from the archive for the Argon2id salt and
   parameters.
2. Re-derive the KEK: `KEK = argon2id(passphrase, salt, time=3, memory=64MiB, threads=4, keyLen=32)`.
3. For each credential entry, split the payload as `nonce[24] || ciphertext`, then:
   `plaintext = XChaCha20Poly1305_Open(kek, nonce, ciphertext, AAD=<entry-path>)`.

The restore command (`keylatch restore`) automates this process.

---

### `keylatch test`

Test a connection against the provider's validation endpoint.

```
keylatch test <connection> [--namespace <ns>]
```

---

### `keylatch status`

Show connection health for all configured providers.

```
keylatch status [--namespace <ns>] [--test] [--json]
```

| Flag | Description |
|------|-------------|
| `--test` | Run live validation tests before reporting |
| `--namespace` | Restrict to a specific namespace (default: `default`) |

---

### `keylatch describe`

Describe a connection or provider template. No secret values are returned.

```
keylatch describe <connection-or-provider> [--json]
```

---

### `keylatch list`

List stored credential connections.

```
keylatch list [--json] [--namespace <ns>]
```

Field values are never included in list output.

---

### `keylatch validate`

Validate connections against their provider schemas.

```
keylatch validate [--namespace <ns>] [--strict]
```

---

### `keylatch call`

Dispatch a single named HTTP action from a provider's action catalog.

Full reference and action catalog: [docs/call.md](call.md)

```
keylatch call <connection> <action> [--param key=value]... [--list] [--json] [--include-headers]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--param key=value` | | Action parameter (key=value). Repeat for multiple params. |
| `--runtime <mode>` | | Override runtime mode for this call. |
| `--list` | `false` | List available actions for the connection and exit. |
| `--json` | `false` | Output as JSON Lines (`{"status_code":200,"duration_ms":42,"body":{...}}`). |
| `--include-headers` | `false` | Append a trailing headers JSON line (Authorization stripped). |
| `--namespace` | `default` | Vault namespace. |
| `--account` | | Account name for multi-account providers. |

**Examples**

```bash
# List available actions for openai.
keylatch call openai --list

# Call the list-models action.
keylatch call openai list-models

# Call with a query param and JSON output.
keylatch call openai list-files --param purpose=fine-tune --json

# All headline providers.
keylatch call anthropic list-models
keylatch call openrouter list-models
```

**Exit codes**

| Code | Meaning |
|------|---------|
| `0` | Success (2xx) |
| `1` | Non-2xx response or argument error |
| `3` | Credential not found in vault |
| `5` | Dispatch failed (network error) |

---

### `keylatch run`

Run a subprocess with injected credentials.

```
keylatch run <connection> [--runtime <mode>] [--dry-run] [--json] [--clean-env] [--extra <var>] -- <command> [args...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--runtime` | `gateway_typed` | Runtime mode (see `keylatch modes`) |
| `--dry-run` | `false` | Show what would be injected and executed without running the command. Exits 0 if the plan is executable, non-zero otherwise (SecretNotFound=6, BootstrapMissing=7, RuntimeNotAvailable=5). |
| `--json` | `false` | Output dry-run plan as JSON (requires `--dry-run`) |
| `--clean-env` | `false` | Minimal child environment (PATH, HOME, USER, SHELL, TERM, LANG, and injected vars) |
| `--extra <var>` | | Preserve a specific variable when using `--clean-env`. Repeatable. |
| `--allow <prefix>` | | Allow an extra command prefix for this run only (blocked in LLM sessions). Repeatable. |

**`--dry-run` behaviour**

When `--dry-run` is set, keylatch:
1. Resolves the connection (finds which backend/provider template to use).
2. Resolves the runtime mode (which driver would be selected).
3. Runs pre-flight checks (LLM guard, policy) but does **not** decrypt credentials or exec the child process.
4. Prints the execution plan. Sensitive values (credentials, gateway tokens) are **never** shown — only redacted placeholders.

**`--dry-run --json` output schema (v1)**

```json
{
  "_schema": "v1",
  "plan": {
    "_schema": "v1",
    "runtime": "gateway_typed",
    "provider": "openrouter",
    "connection": "openrouter",
    "env_added": [
      "KEYLATCH_GATEWAY_URL=<resolved: http://127.0.0.1:7878>",
      "KEYLATCH_GATEWAY_TOKEN=<would-be-issued scope:openrouter.*, ttl:1h>",
      "KEYLATCH_RUNTIME=gateway_typed"
    ],
    "env_stripped": ["KEYLATCH_GATEWAY_TOKEN"],
    "argv": ["node", "script.js"],
    "policy": {
      "llm_session": false,
      "approval_required": false
    }
  }
}
```

Fields:
- `runtime` — chosen mode name (e.g. `"gateway_typed"`)
- `provider` — provider/connection identifier
- `connection` — connection identifier (same as provider in current MVP)
- `env_added` — list of env var assignments that would be made (values are redacted placeholders for sensitive vars; gateway token shown as `<would-be-issued scope:..., ttl:...>`)
- `env_stripped` — list of `KEYLATCH_*` vars from the parent environment that would be stripped before child exec
- `argv` — the full argv that would be exec'd
- `policy.llm_session` — whether the current session is detected as an LLM session
- `policy.approval_required` — whether an approval JWT was supplied

**Examples**

```bash
keylatch run openrouter -- node script.js
keylatch run openrouter --dry-run -- node script.js
keylatch run openrouter --dry-run --json -- node script.js
keylatch run openrouter --runtime gateway_sdk -- python main.py
keylatch run aws-prod --runtime direct_brokered -- ./deploy.sh
keylatch run openrouter --clean-env -- node script.js
keylatch run openrouter --clean-env --extra DATABASE_URL -- node script.js
```

---

## Runtime errors

When keylatch encounters a structured runtime error (e.g. gateway not running, secret not found, token mint failure), it prints to stderr in the canonical format:

```
error[<Class>]: <provider> + <mode>: <reason>. <fix-hint>
```

Examples:

```
error[RuntimeNotAvailable]: anthropic + gateway_typed: gateway is not running. Try: keylatch gateway up
error[SecretNotFound]: openrouter + direct_brokered: no credential found for this connection. Try: keylatch connect openrouter --field api_key=@prompt
error[RuntimeNotAvailable]: openrouter + gateway_sdk: failed to mint session token. Run: keylatch doctor --category runtime
```

**Exit codes for runtime errors**

| Class | Exit code | Meaning |
|-------|-----------|---------|
| `RuntimeNotAvailable` | 5 | Mode unavailable (gateway down, mode removed) |
| `GatewayNotRunning` | 5 | Gateway process not running |
| `SecretNotFound` | 6 | No credential stored for this connection |
| `BootstrapMissing` | 7 | `keylatch bootstrap` has not been run |
| `PolicyDeny` | 3 | Policy explicitly denied the request |
| `SecurityBlock` | 2 | Blocked by LLM session guard |
| `ApprovalRequired` | 4 | Human approval required |
| `InternalError` | 9 | Unexpected internal failure |

---

### `keylatch get`

Retrieve a credential value. **Blocked in LLM sessions (exit 2).** The unmasked path is not yet implemented — exits 5 (`OperationFailed`) outside LLM sessions.

```
keylatch get <service> <key> [--masked]
```

| Flag | Description |
|------|-------------|
| `--masked` | Return masked value (`****`) — fully implemented, safe in all sessions including LLM |

---

### `keylatch get-masked`

Retrieve a masked credential value (`****`). Safe in LLM sessions. Equivalent to `keylatch get <service> <key> --masked`.

```
keylatch get-masked <service> <key>
```

---

### `keylatch set`

Write a credential value.

```
keylatch set <service> <key>    # prompts for value
```

---

### `keylatch versions`

List versions of a stored credential.

```
keylatch versions <path> [--json]
```

---

### `keylatch rollback`

Roll back a credential to a previous version.

```
keylatch rollback <path> <version>
```

---

### `keylatch destroy-version`

Delete a specific version of a credential.

```
keylatch destroy-version <path> <version>
```

---

### `keylatch check-expiry`

Warn about credentials expiring within the configured window.

```
keylatch check-expiry [--days <n>] [--json]
```

---

### `keylatch config`

Manage keylatch configuration.

```
keylatch config list
keylatch config get <key>
keylatch config set <key> <value>
```

**Examples**

```bash
keylatch config list
keylatch config get backend
keylatch config set backend file
keylatch config set backend keychain
```

Credential keys are rejected — use `keylatch set` for credentials.

---

### `keylatch approve`

Approve a pending secret-access request by token. **Blocked in LLM sessions.**

```
keylatch approve <token> [--reason <text>] [--json]
```

| Flag | Description |
|------|-------------|
| `--reason <text>` | Record a reason for the approval |
| `--json` | Output result as JSON |

#### `keylatch approve list`

List all pending approval requests.

```
keylatch approve list [--json]
```

Columns: `ID | PROVIDER | AGENT | REQUESTED-AT | TTL-REMAINING | STATUS`

Entries past their TTL show `STATUS=expired` and can no longer be acted upon.

---

### `keylatch deny`

Deny a pending secret-access request by token. **Blocked in LLM sessions.**

```
keylatch deny <token> [--reason <text>] [--json]
keylatch deny --all [--yes] [--json]
```

| Flag | Description |
|------|-------------|
| `--reason <text>` | Record a reason for the denial |
| `--all` | Deny all pending approvals |
| `--yes` | Skip the `--all` confirmation prompt |
| `--json` | Output result as JSON (`{deniedCount, requestIds}` for `--all`) |

See [approval.md](approval.md) for full approval system documentation including TTL, auto-deny, and policy modes.

---

### `keylatch audit`

View the local audit log (value-free).

```
keylatch audit [--summary] [--since <time>] [--json]
```

---

### `keylatch ui`

Start the local browser UI.

```
keylatch ui [--port <n>] [--scope <scope>] [--demo] [--no-open] [--unsafe-bind-all]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `7890` | Port to listen on |
| `--scope` | `admin` | Session scope: `status-only`, `setup`, `admin`, `token-minting` |
| `--demo` | | Run with stub data |
| `--no-open` | | Print URL without opening browser |
| `--unsafe-bind-all` | | Bind to `0.0.0.0` (non-LLM sessions only) |

In an LLM session, scope is forced to `status-only` and `--unsafe-bind-all` is ignored.

---

### `keylatch gateway`

Manage the local typed provider gateway.

```
keylatch gateway <subcommand>
```

#### `gateway init`

```
keylatch gateway init [--docker]
```

Generates the gateway signing key at `~/.keylatch/gateway/signing.key` and writes `gateway-config.json`. With `--docker`, also writes a Docker Compose file.

#### `gateway up`

```
keylatch gateway up [--port <n>] [--detach] [--unsafe-bind-all]
```

Starts the local process gateway. Binds to `127.0.0.1:<port>` by default.
The gateway reads credentials from the AEAD-encrypted vault at the canonical
path `<namespace>/<category>/<provider>/<field>` (e.g. `default/ai/openrouter/api_key`).

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `7878` | Port to listen on |
| `--detach` | | Background mode (stub in current release) |
| `--unsafe-bind-all` | | Bind to `0.0.0.0` (non-LLM sessions only) |

#### `gateway down`

```
keylatch gateway down
```

Sends SIGTERM to the running gateway process.

#### `gateway status`

```
keylatch gateway status
```

Reports running state and active token count. No credential values.

#### `gateway token create`

```
keylatch gateway token create <actor> [--allow <capability>] [--ttl <duration>] [--max-uses <n>]
```

Mints a new gateway token (`KEYLATCH_GATEWAY_TOKEN`). The JWT is printed once — it is never stored in plaintext. Set `KEYLATCH_GATEWAY_TOKEN=<jwt>` in your agent environment.

**Token security properties:**

- **TTL** (`--ttl`): The token expires after the declared duration. Expired tokens return `401 token_expired`.
- **Scope** (`--allow`): Each token is scoped to one or more capabilities (`<provider>.<action>`). Requests outside scope return `403 capability_mismatch`.
- **Audience isolation**: The capability format `<provider>.<action>` prevents cross-provider use.
- **Replay protection** (`--max-uses`): Tokens with `--max-uses N` are accepted at most N times. Replay returns `401 token_exhausted`.
- **Revocation**: Use `gateway token revoke <accessor>` to end a session. Revoked tokens return `401 token_revoked`.

| Flag | Default | Description |
|------|---------|-------------|
| `--allow` | | Capability to allow (e.g. `openrouter.chat.completion`). Repeatable. |
| `--ttl` | `1h` | Token TTL (e.g. `1h`, `30m`) |
| `--max-uses` | `0` (unlimited) | Maximum uses. LLM sessions cannot create unlimited tokens. |

#### `gateway token list`

```
keylatch gateway token list [--json]
```

Lists active tokens without JWT values.

#### `gateway token revoke`

```
keylatch gateway token revoke <accessor-id>
```

#### `gateway logs`

```
keylatch gateway logs [--follow]
```

---

### `keylatch runtime`

Subcommands for runtime mode management.

#### `runtime doctor`

```
keylatch runtime doctor [--json]
```

Diagnose runtime mode configuration and gateway connectivity.

---

### `keylatch registry`

Inspect and validate the provider template registry.

#### `registry validate`

```
keylatch registry validate <path>
```

Validates a provider template YAML against the JSON Schema. Exits `0` on success, `1` on failure.

#### `registry list`

```
keylatch registry list [--json]
```

Lists all registered providers.

---

### `keylatch agent`

Agent profile setup commands.

```
keylatch agent setup <name> --mode <mcp|env> [--dry-run] [--namespace <ns>]
```

Supported agent names: `claude-code`, `codex`, `cursor`, `openhands`.

---

### `keylatch mcp`

Start the Keylatch MCP server.

```
keylatch mcp --stdio
```

Exposes 5 tools: connection status, capability check, policy evaluation, run-under-keylatch, and receipt retrieval. Never exposes secret values.

---

### `keylatch policy`

Manage runtime access policies.

```
keylatch policy allow <actor> <path> [--capability <cap>] [--command <cmd>] [--ttl <duration>]
keylatch policy list [--actor <actor>] [--json]
keylatch policy revoke <id>
```

---

### `keylatch grant`

List and revoke capability grants.

```
keylatch grant list [--json]
keylatch grant revoke <id>
```

---

### `keylatch broker`

Inspect and manage the in-process token broker cache. Subcommands operate on
metadata only — no credential values are emitted.

**Requires the broker to be running in-process.** If the broker is owned by a
separate gateway process, use `keylatch gateway status` instead. Out-of-process
calls return exit code 2 with an actionable error message.

#### `broker status`

```
keylatch broker status [--json]
```

List all active scoped tokens managed by the in-process broker.

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON (`{grants:[...], total:N}`) |

**Table columns:** `PROVIDER | ACTOR-HMAC | SCOPED-TOKEN-ID | EXPIRES-AT | INSERTED-AT`

No credential values (raw tokens, JWTs, API keys) are ever included in the output.
Actor IDs are HMAC-hashed; the raw actor string never appears.

**Empty state:** Prints `No active scoped tokens.` and exits 0.

**Out-of-process:** Exits 2 (`SecurityBlock`) with an actionable error.

**Example:**

```bash
keylatch broker status
keylatch broker status --json
```

#### `broker dry-run`

```
keylatch broker dry-run <provider> <command> [--json]
```

Simulate a broker token exchange for a provider and command **without issuing a
token**. Does not call the provider token endpoint and does not mutate the cache.
Emits a `broker.dry_run_requested` audit event.

| Argument | Description |
|----------|-------------|
| `<provider>` | Provider slug (e.g. `openrouter`, `github`) |
| `<command>` | Command string the actor would run (used to derive scopes) |

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |

**Table columns:** `FIELD | VALUE` (provider, command, scopes\_requested, scoped\_token\_ttl, policy\_decision, reason)

**Error exits:**
- Exit 1 (`UserError`) — provider has no broker configuration
- Exit 2 (`SecurityBlock`) — broker not running in-process

**Examples:**

```bash
keylatch broker dry-run openrouter "node script.js"
keylatch broker dry-run github "gh pr list" --json
```

#### `broker revoke`

```
keylatch broker revoke <id> [--json]
keylatch broker revoke --all [--yes] [--json] [--actor <id>]
```

Revoke an active scoped token by ID, or revoke all active tokens.

The `<id>` argument is the `SCOPED-TOKEN-ID` shown by `broker status`.

**Single token revoke:**
- Marks the token revoked and evicts it from the cache.
- Attempts provider-side revocation if the provider template declares a
  revocation endpoint (best-effort; logged on failure).
- Emits a `broker.token_revoked` audit event.

| Argument | Description |
|----------|-------------|
| `<id>` | Scoped-Token-ID from `broker status` |

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON (`{token_id, status}`) |

**Error exits:**
- Exit 1 (`UserError`) — token not found or already revoked
- Exit 2 (`SecurityBlock`) — broker not running in-process

**Revoke all (`--all`):**

```
keylatch broker revoke --all [--yes] [--json] [--actor <id>]
```

Lists all active grants and prompts `Revoke all N? [y/N]`.

| Flag | Description |
|------|-------------|
| `--all` | Revoke all active tokens |
| `--yes` | Skip confirmation prompt |
| `--actor` | Filter to tokens for this actor ID only |
| `--json` | Output as JSON (`{revokedCount, tokenIds}`) |

Race tolerance: tokens that expire between listing and revoking are skipped silently.

**Examples:**

```bash
keylatch broker revoke tok_abc123
keylatch broker revoke tok_abc123 --json
keylatch broker revoke --all
keylatch broker revoke --all --yes
keylatch broker revoke --all --yes --json
keylatch broker revoke --all --actor alice --yes
```

---

### `keylatch trust`

Root-of-trust management.

```
keylatch trust list              # List configured roots
keylatch trust status            # Health check all roots
keylatch trust add <type>        # Configure a new root (passphrase, keychain, op, bw, pkcs11, ...)
keylatch trust remove <id>       # Remove a root configuration
```

---

### `keylatch team`

Team governance commands (requires team mode).

```
keylatch team status
keylatch team policy baseline
keylatch team actors list
keylatch team access-review
```

---

### `keylatch receipts`

View run receipts. Receipts are value-free audit records emitted for every policy-gated execution. Credential values never appear in receipt output (S-RM-9).

#### `keylatch receipts list`

```
keylatch receipts list [--limit N] [--json]
```

List run receipts from the local file store.

| Flag | Default | Description |
|------|---------|-------------|
| `--limit N` | `50` | Maximum number of receipts to show |
| `--json` | — | Output as a JSON array |

**Example — table output:**

```
TIMESTAMP                ACTOR       CONNECTION    CAPABILITY  DECISION  EXIT
2026-05-18T12:00:00Z     alice       anthropic     messages    allowed   0
2026-05-18T11:59:00Z     alice       openai        embed       allowed   0
```

**Example — JSON output:**

```bash
keylatch receipts list --json --limit 10
```

```json
[
  {
    "actor": "alice",
    "connection": "anthropic",
    "capability": "messages",
    "policy_decision": "allowed",
    "exit_code": 0,
    "timestamp": "2026-05-18T12:00:00Z"
  }
]
```

#### `keylatch receipts tail`

```
keylatch receipts tail [--follow]
```

Tail run receipts.

| Flag | Description |
|------|-------------|
| `--follow`, `-f` | Follow live events via SSE from keylatchd |

**Without `--follow`**: prints the latest 10 receipts from the local file store and exits.

**With `--follow`**: connects to the keylatchd SSE endpoint (`/v1/receipts/stream`) and prints each incoming receipt as a newline-delimited JSON object. Press Ctrl-C to stop.

The gateway address is read from `KEYLATCH_UI_ADDR` (default `127.0.0.1:7890`).

**Example:**

```bash
keylatch receipts tail --follow
```

```json
{"runtime":"gateway_typed","provider":"anthropic","capability":"messages","policy_decision":"allowed","credential_shape":"bearer","exit_code":0}
{"runtime":"gateway_typed","provider":"openai","capability":"embed","policy_decision":"allowed","credential_shape":"bearer","exit_code":0}
```

---

### `keylatch keychain-init`

Initialize or verify the dedicated Keylatch keychain (`~/.keylatch/keylatch.keychain-db`).

```
keylatch keychain-init [service] [--verify-acl] [--force]
```

Safe to re-run (e.g. during `keylatch setup`): if a working unlock credential
already exists, `keychain-init` reuses it and only repairs the ACL — it never
generates a new one unless neither the keychain-db nor the login-keychain
unlock item exists yet. Re-running it never orphans secrets stored under the
current credential.

`--force` regenerates the unlock credential unconditionally, even if this would
orphan secrets stored under the current one. Only use it after confirming you
accept that data loss (e.g. the login-keychain unlock item was lost or
corrupted and the existing keychain-db is unrecoverable anyway).

### `keylatch keychain-repair-acl`

Re-issue the keychain ACL for the current binary path (after moving or re-signing the binary).

```
keylatch keychain-repair-acl
```

### `keylatch keychain-list`

List all `keylatch-*` items in the custom keychain (names only, no values).

```
keylatch keychain-list
```

### `keylatch keychain-clear`

Remove all keys for one service from the keychain.

```
keylatch keychain-clear <service>
```

---

### `keylatch completion`

Generate shell completion scripts.

```
keylatch completion <shell>
```

Supported: `zsh`, `bash`, `fish`, `pwsh`.

---

## See also

- [Getting Started](getting-started.md)
- [Provider Templates](provider-templates.md)
- [Security](security.md)
- [SECURITY.md](../SECURITY.md)
