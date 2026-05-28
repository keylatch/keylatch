# Getting Started

## Installation

### Homebrew (macOS / Linux)

```bash
brew install keylatch/tap/keylatch
```

### Binary download

Download the latest release from the [releases page](https://github.com/keylatch/keylatch/releases). Verify the checksum before running:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

### Scoop (Windows)

```powershell
scoop bucket add keylatch https://github.com/keylatch/scoop-bucket
scoop install keylatch
```

### Build from source

Requires Go 1.25+.

```bash
go install github.com/keylatch/keylatch/cmd/keylatch@latest
```

---

## First-time setup

### 1. Bootstrap

`bootstrap` creates the local configuration directory (`~/.keylatch/`) with correct permissions, initializes the config file, and sets up the audit log. This must be run before `keylatch run` or `keylatch setup`.

```bash
keylatch bootstrap
```

To preview what bootstrap will do without writing anything:

```bash
keylatch bootstrap --dry-run --json
```

### 2. Run the setup wizard

The interactive setup wizard walks you through backend configuration and provider connection in five steps. At the start of the wizard you choose how to store credentials:

```
Store credentials locally (AEAD) or reference from a password manager? [local/reference/q]
```

**Local branch** — AEAD-encrypts the secret and stores it in your chosen backend (file, macOS Keychain, 1Password, Bitwarden). The wizard then guides you through:

```
[1/5] Detecting platform...
[2/5] Backend setup...
[3/5] Daemon setup...
[4/5] Connect your first provider...
[5/5] Open Keylatch app (optional)...
```

Run interactively:

```bash
keylatch setup
```

Non-interactive (CI-safe):

```bash
keylatch setup --non-interactive --backend file
```

**Reference branch** — stores a URI that resolves at runtime via an external password manager. Supported URI schemes: `op://`, `aws-sm://`, `hashivault://`.

```
Provider reference URI: op://Private/Anthropic/api_key
```

The wizard validates the URI format and performs a dry-run resolution to check that the external CLI is reachable. The URI is stored; the plaintext secret is never written to disk.

Then connect a provider using the stored reference:

```bash
keylatch connect anthropic --provider-ref api_key=op://Private/Anthropic/api_key
```

### 3. Choose a backend

Set `KEYLATCH_BACKEND` in your shell profile, or run:

```bash
keylatch config set backend file       # encrypted local file (default, works everywhere)
keylatch config set backend keychain   # macOS Keychain (macOS only)
keylatch config set backend op         # 1Password CLI
keylatch config set backend bw         # Bitwarden / Vaultwarden
```

### 4. Verify your setup

```bash
keylatch doctor
```

Doctor checks backend availability, config file integrity, audit log permissions, and LLM session guard status. Use `--json` for machine-readable output.

### First-run guard

`keylatch run` enforces three sequential pre-flight checks before injecting any credential:

1. **Bootstrap check** (exit 7): `~/.keylatch/keyring.json` must exist. If not, run `keylatch bootstrap`.
2. **Connection check** (exit 6): A connection for the requested provider must exist. If not, run `keylatch setup <provider>`.
3. **Runtime check** (exit 5): The requested runtime mode must be available.

These checks ensure a clean error message on a fresh machine instead of a confusing nil-pointer or missing-file error.

---

## Connecting a provider

Register a credential under a provider name:

```bash
# Interactive prompt (recommended — no shell history exposure):
keylatch connect openrouter

# Or via stdin (CI-safe):
printf '%s' "$OPENROUTER_API_KEY" | keylatch connect openrouter -f api_key=@-

# Or via --provider-ref (pulls directly from 1Password / AWS Secrets Manager):
keylatch connect openrouter --provider-ref api_key=op://vault/openrouter/credential
```

The key is stored encrypted in your chosen backend. Keylatch never writes plaintext to disk.

After connecting, test the connection:

```bash
keylatch test openrouter
```

List all connections:

```bash
keylatch list
```

Diagnose which runtime modes are available for a provider:

```bash
keylatch runtime doctor openrouter
```

This reports which modes are declared in the provider template, which are available given current system state (gateway running? bwrap available?), and why unavailable modes cannot be used. Use `--json` for machine-readable output.

---

## Running a command

Inject a stored credential into a subprocess:

```bash
keylatch run openrouter -- node script.js
```

Keylatch resolves the connection, injects the credential into the subprocess environment, and exits when the subprocess exits.

**In an LLM session** (Claude Code, Codex, Cursor): the default `gateway_typed` mode is allowed. Direct extraction via `keylatch get` is blocked (exit code 2).

### Runtime modes

```bash
# Default: typed gateway
keylatch run openrouter -- node script.js

# SDK-compatible gateway
keylatch run openrouter --runtime gateway_sdk -- python main.py

# Direct brokered injection (trusted broker process required)
keylatch run aws-prod --runtime direct_brokered -- ./deploy.sh
```

See the [CLI reference](./cli-reference.md#runtime-modes) for the full runtime mode matrix.

---

## Using the browser UI

```bash
keylatch ui
```

Opens the Keylatch browser UI at `127.0.0.1:7890`. Supports:
- Viewing and managing connections
- Reviewing pending approvals
- Setting up agent profiles for Claude Code, Codex, Cursor, and OpenHands
- Demo mode for onboarding (`--demo`)

In an LLM session, the UI starts in `status-only` scope — write endpoints return 404.

---

## Setting up the local gateway

The local gateway lets agent processes receive a scoped session token instead of a raw credential:

```bash
# Initialize (generates signing key at ~/.keylatch/gateway/)
keylatch gateway init

# Start in foreground (binds to 127.0.0.1:7878)
keylatch gateway up

# Start in background — returns to shell immediately
keylatch gateway up --detach

# Mint a 1-hour token for a specific capability
keylatch gateway token create claude-code --allow openrouter.chat --ttl 1h

# Check status
keylatch gateway status

# Stop the running gateway
keylatch gateway down
```

---

## Setting up an agent profile

Generate an MCP config snippet for your agent:

```bash
keylatch agent setup claude-code --mode mcp --dry-run  # preview
keylatch agent setup claude-code --mode mcp             # write to ~/.claude/mcp.json
```

Supported agents: `claude-code`, `codex`, `cursor`, `openhands`.

---

## Shell completions

```bash
# Zsh
keylatch completion zsh > ~/.zsh/_keylatch
echo 'fpath=(~/.zsh $fpath)' >> ~/.zshrc
echo 'autoload -U compinit && compinit' >> ~/.zshrc

# Bash
source <(keylatch completion bash)

# Fish
keylatch completion fish > ~/.config/fish/completions/keylatch.fish

# PowerShell
keylatch completion pwsh | Out-File $PROFILE -Append
```

---

## Next steps

- [CLI Reference](./cli-reference.md) — full command, flag, and exit code reference
- [Provider Templates](./provider-templates.md) — add or validate provider templates
- [Security](./security.md) — artifact signing, FIPS builds, and SBOM
