# Keylatch

**Zero-trust credential vault for AI-assisted development.** Keylatch stores your API keys and secrets in an encrypted backend (macOS Keychain, 1Password, Bitwarden, or an encrypted file), then injects them into subprocesses at runtime. LLM session detection — Claude Code, Codex, Cursor, and others — blocks direct credential access automatically. Your keys never appear in model context, MCP tool outputs, or agent logs.

```
┌─────────────────────────────────────────────────────────────┐
│  Encrypted vault (Keychain / 1Password / Bitwarden / file)  │
│    → Keylatch core (policy + audit)                         │
│      → keylatch run injects scoped env vars into subprocess │
│        → script / MCP server reads process.env.SOME_KEY     │
│          → (gateway mode) local gateway → provider API      │
└─────────────────────────────────────────────────────────────┘
```

[![Secured by Keylatch](https://img.shields.io/badge/secured%20by-keylatch-blue)](https://keylatch.dev)

## Using Keylatch with Claude Code?

One command protects you from agent-driven credential exfiltration:

```bash
keylatch install-guard claude-code
```

This wires a `PreToolUse` hook into Claude Code that blocks credential access patterns before they execute. See [docs/integrations/claude-code.md](docs/integrations/claude-code.md) for details.

## Install

Keylatch ships as a **self-contained CLI** (macOS, Windows, Linux), a **Docker image**, and a **Linux desktop app**. The CLI is the complete product — `keylatch ui` opens the full browser GUI, so no separate desktop app is required. Native macOS/Windows desktop apps are planned for a post-MVP release; on those platforms, use the CLI.

### Homebrew (macOS / Linux)

```bash
brew install keylatch/tap/keylatch
```

### Binary download

Download the latest release from the [releases page](https://github.com/keylatch/keylatch/releases) and verify the checksum:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

Verify the release artifact with cosign (keyless signing via GitHub Actions OIDC):

```bash
cosign verify-blob \
  --certificate-identity-regexp="github.com/keylatch" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  <artifact> \
  --signature <artifact>.sig
```

> **Note on signing:** All release artifacts — CLI archives, checksums, the SBOM, and the
> Linux desktop bundle — are cosign-signed; see [Verifying releases](docs/verifying-releases.md)
> and [How signing works](docs/architecture/signing.md). The CLI is **not** OS code-signed:
> install via **Homebrew or Scoop** to avoid any Gatekeeper/SmartScreen friction, or if you
> download the raw macOS binary directly, run `xattr -dr com.apple.quarantine ./keylatch`.
> Native macOS/Windows **desktop apps** (with Apple notarization / Windows Authenticode) are
> planned for a post-MVP release.

### Scoop (Windows)

```powershell
scoop bucket add keylatch https://github.com/keylatch/scoop-bucket
scoop install keylatch
```

### Docker

```bash
docker pull ghcr.io/keylatch/keylatch:latest
docker run --rm ghcr.io/keylatch/keylatch:latest --help
```

### Desktop app (Linux)

Download `Keylatch_<version>_amd64.AppImage` or `Keylatch_<version>_amd64.deb` from the [releases page](https://github.com/keylatch/keylatch/releases). macOS and Windows desktop apps are coming in a later release — on those platforms, use the CLI (`keylatch ui` provides the same browser GUI).

### Build from source

```bash
go install github.com/keylatch/keylatch/cmd/keylatch@latest
```

## Quickstart

```bash
# 1. First-time setup
keylatch setup

# 2. Store a credential interactively
keylatch connect openrouter

# 3. Preview what would be injected (dry-run)
keylatch run openrouter --dry-run -- node script.js

# 4. Run with credentials injected
keylatch run openrouter -- node script.js

# 5. Verify your setup
keylatch doctor
```

## Core concepts

### Backends

Keylatch never stores credentials in plaintext. Choose a backend that matches your environment:

| Backend | Env / Config | Platform |
|---------|-------------|----------|
| Encrypted file (XChaCha20-Poly1305) | `KEYLATCH_BACKEND=file` | All |
| macOS Keychain | `KEYLATCH_BACKEND=keychain` | macOS only |
| 1Password CLI | `KEYLATCH_BACKEND=op` | All |
| Bitwarden / Vaultwarden | `KEYLATCH_BACKEND=bw` | All |

Set `KEYLATCH_BACKEND` in your environment or configure `backend` in `~/.keylatch/config.json`.

### Runtime modes

`keylatch run` enforces an access model that controls how credentials reach child processes:

| Mode | Flag | Description |
|------|------|-------------|
| `gateway_typed` | `--runtime gateway_typed` | Default. Credential injected via local typed gateway with schema validation. |
| `gateway_sdk` | `--runtime gateway_sdk` | SDK-compatible credential exchange through the gateway. |
| `direct_brokered` | `--runtime direct_brokered` | Direct injection via trusted broker process. |
| `gateway_proxy` | `--runtime gateway_proxy` | Credential proxy through the local gateway. |
| `direct_classic_sandboxed` | `--runtime direct_classic_sandboxed` | Isolated subprocess via OS sandbox (bwrap on Linux, sandbox-exec on macOS). |

In any detected LLM session (Claude Code, Codex, Cursor, Aider, Gemini CLI, OpenCode, `CREDENTIALS_LLM_SESSION`), all four modes are permitted. Gateway modes are recommended for LLM sessions because credentials never leave the gateway process.

### LLM session guard

#### Supported agents

| Agent | Auto-Detected | Hook Available | Notes |
|-------|--------------|---------------|-------|
| [Claude Code](docs/integrations/claude-code.md) | Yes | Yes | Detected via `CLAUDE_CODE` env var |
| [Codex](docs/integrations/codex.md) | Yes | Yes | Detected via `CODEX_ENV` env var |
| [Cursor](docs/integrations/cursor.md) | Yes | Yes | Detected via `CURSOR_SESSION` env var |
| [Aider](docs/integrations/aider.md) | Yes | Yes | Detected via `AIDER_SESSION` env var |
| [Gemini](docs/integrations/gemini.md) | Yes | Yes | Detected via `GEMINI_SESSION` env var |
| [OpenCode](docs/integrations/opencode.md) | Yes | Yes | Detected via `OPENCODE_SESSION` env var |
| [Windsurf](docs/integrations/windsurf.md) | No | No | Set `CREDENTIALS_LLM_SESSION=windsurf` in shell rc |
| [Antigravity](docs/integrations/antigravity.md) | No | No | Set `CREDENTIALS_LLM_SESSION=antigravity` in shell rc |
| [GitHub Copilot](docs/integrations/copilot.md) | No | No | Set `CREDENTIALS_LLM_SESSION=copilot` in shell rc |
| Generic | Yes | N/A | Any tool that sets `CREDENTIALS_LLM_SESSION` to a non-empty value |

Keylatch detects active LLM sessions via environment signals (`CLAUDE_CODE`, `CODEX_ENV`, `CREDENTIALS_LLM_SESSION`, `CURSOR_SESSION`, `AIDER_SESSION`, `GEMINI_SESSION`, `OPENCODE_SESSION`). When a session is detected:

- `keylatch get` — blocked, exit code 2 (SecurityBlock)
- `keylatch run` — allowed for all v1.0.0 runtime modes
- `keylatch ui` — scope locked to `status-only` (read-only)
- `keylatch gateway token create` — `--max-uses=0` (unlimited) tokens are rejected

### Local gateway

The local gateway mediates credential access. Agent processes receive a short-lived Keylatch session token and a gateway URL — not the raw provider key.

```bash
# Initialize the gateway (generates signing key)
keylatch gateway init

# Start in foreground (binds to 127.0.0.1:7878)
keylatch gateway up

# Start in background — returns to shell immediately, writes PID to ~/.keylatch/gateway/gateway.pid
keylatch gateway up --detach

# Mint a scoped gateway token for an agent
keylatch gateway token create claude-code --allow openrouter.chat --ttl 1h

# Check status
keylatch gateway status

# Stop the running gateway (sends SIGTERM, removes PID file)
keylatch gateway down
```

### Runtime diagnostics

```bash
# Diagnose which runtime modes are available for a provider
keylatch runtime doctor openrouter

# JSON output for scripting
keylatch runtime doctor openrouter --json
```

Reports: which modes are in the provider's `runtime_support`, which are available given current system state (gateway running? bwrap available?), and why unavailable modes cannot be used.

### Browser UI

```bash
keylatch ui
```

Opens a browser UI at `127.0.0.1:7890` for managing connections, reviewing pending approvals, and setting up agent profiles — no CLI required for day-to-day use.

```bash
keylatch ui --demo     # Explore with stub data
keylatch ui --no-open  # Print URL without opening browser
```

## CLI reference

### Setup and diagnostics

```bash
keylatch setup                                 # Guided first-time setup (interactive)
keylatch bootstrap [--dry-run] [--json]        # Initialize configuration (scriptable)
keylatch doctor [--json]                       # Diagnose configuration and environment
keylatch doctor --category runtime             # Check runtime mode availability
```

### Connection management

```bash
keylatch connect <provider>                              # Store a credential (interactive)
keylatch connect <provider> -f api_key=@-               # Read from stdin (CI-safe)
keylatch connect <provider> -f api_key=@prompt          # Interactive secure prompt
keylatch connect <provider> --provider-ref api_key=op://vault/item/field   # From 1Password
keylatch connect <provider> --provider-ref api_key=aws-sm://region/secret  # From AWS SM
keylatch connect <provider> --provider-ref api_key=hashivault://mount/path#field  # From Vault
keylatch list                                            # List all connections
keylatch status                                          # Health check all connections
keylatch validate                                        # Validate against provider schemas
keylatch test <connection>                               # Test a specific connection
```

### Credential operations

```bash
keylatch get <service> <key> --masked          # Retrieve masked value (safe everywhere)
keylatch get-masked <service> <key>            # Alias — masked retrieval, safe in LLM sessions
keylatch set <service> <key>                   # Write a credential
keylatch run <connection> -- <cmd>             # Run a subprocess with injected credentials
keylatch run <connection> --dry-run -- <cmd>   # Preview injection without running
keylatch run <connection> --dry-run --json -- <cmd>  # Preview as JSON
keylatch run <connection> --clean-env -- <cmd>  # Minimal child environment (PATH, HOME, USER)
keylatch run <connection> --clean-env --extra SOME_VAR -- <cmd>  # Preserve specific vars
keylatch call <connection> <action>            # Dispatch a single provider action (see docs/call.md)
keylatch call <connection> --list             # List available actions for a connection
```

### Configuration

```bash
keylatch config set backend <name>             # Change credential backend
keylatch runtime doctor <provider>             # Diagnose runtime mode availability
```

### Versioning and expiry

```bash
keylatch versions <path>                       # List versions of a credential
keylatch rollback <path> <version>             # Roll back to a previous version
keylatch destroy-version <path> <version>      # Delete a specific version
keylatch check-expiry                          # Warn about expiring credentials
```

### Audit

```bash
keylatch audit                                # View local audit log
keylatch audit --summary                      # Summarize audit events
keylatch audit tail                           # Stream live audit events
```

### Registry

```bash
keylatch registry validate <path>             # Validate a provider template YAML
keylatch registry list                        # List all registered providers
```

### Gateway

```bash
keylatch gateway init [--docker]              # Initialize gateway (+ optional Compose file)
keylatch gateway up [--port 7878] [--detach]  # Start local process gateway
keylatch gateway down                         # Send SIGTERM to gateway
keylatch gateway status                       # Running state + active token count
keylatch gateway token create <actor>         # Mint a scoped gateway token
keylatch gateway token list                   # List active tokens (no JWT values)
keylatch gateway token revoke <id>            # Revoke a token
keylatch gateway logs [--follow]              # View gateway logs
```

### Team governance

```bash
keylatch team status                          # Team and policy status
keylatch policy allow <actor> <path>          # Grant capability
keylatch grant list                           # List active grants
keylatch actors list                          # List registered actors
keylatch sessions list                        # List active sessions
keylatch receipts list                        # List operation receipts (value-free)
```

### Shell completions

```bash
# Zsh
keylatch completion zsh > ~/.zsh/_keylatch

# Bash
source <(keylatch completion bash)

# Fish
keylatch completion fish > ~/.config/fish/completions/keylatch.fish

# PowerShell
keylatch completion pwsh | Out-File $PROFILE -Append
```

## Exit codes

| Code | Name | Meaning |
|------|------|---------|
| `0` | OK | Success |
| `1` | UserError | Invalid input or configuration |
| `2` | SecurityBlock | Blocked by LLM-session guard |
| `3` | Missing | Resource not found |
| `4` | BackendUnavailable | Credential backend unreachable |
| `5` | OperationFailed | Internal or unrecoverable error |

## Backends — advanced configuration

### 1Password (non-interactive / CI)

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
export KEYLATCH_BACKEND=op
keylatch op-list
```

| Variable | Purpose |
|----------|---------|
| `KEYLATCH_OP_VAULT` | Vault name (default: `Keylatch`) |
| `KEYLATCH_OP_BIN` | Path to `op` binary (default: PATH) |
| `OP_SERVICE_ACCOUNT_TOKEN` | Service account token for CI |

### Bitwarden / Vaultwarden

```bash
export BW_SESSION=$(bw unlock --raw)
export KEYLATCH_BACKEND=bw
keylatch bw-list
```

| Variable | Purpose |
|----------|---------|
| `BW_SESSION` | Session token from `bw unlock --raw` |
| `KEYLATCH_BW_SERVER` | Vaultwarden server URL (must be `https://`) |
| `KEYLATCH_BW_BIN` | Path to `bw` binary (default: PATH) |
| `KEYLATCH_BW_FOLDER` | Filter items by folder name |
| `KEYLATCH_BW_COLLECTION` | Filter items by collection ID |

## External store references (`--provider-ref`)

Instead of storing credentials in keylatch's vault directly, you can resolve
them from an external provider at connect time using `--provider-ref field=URI`:

| URI scheme | Provider | Example |
|------------|----------|---------|
| `op://vault/item/field` | 1Password CLI | `--provider-ref api_key=op://Keylatch/openrouter/api_key` |
| `aws-sm://region/secret[#key]` | AWS Secrets Manager | `--provider-ref api_key=aws-sm://us-east-1/myapp/openrouter` |
| `hashivault://mount/path[#field]` | HashiCorp Vault | `--provider-ref api_key=hashivault://secret/myapp/api#key` |

```bash
# Resolve from 1Password and store in keylatch
keylatch connect openrouter --provider-ref api_key=op://Keylatch/openrouter/api_key

# Resolve from AWS Secrets Manager (JSON secret, extract "api_key" field)
keylatch connect openrouter --provider-ref api_key=aws-sm://us-east-1/prod/openrouter#api_key

# Resolve from HashiCorp Vault
keylatch connect openrouter --provider-ref api_key=hashivault://secret/prod/openrouter#api_key
```

The secret is read from the external store at connect time and stored in
keylatch's configured backend. The external CLI (`op`, `aws`, `vault`) must be
on PATH or available at the configured binary path.

## Child process environment hygiene (`--clean-env`)

By default, `keylatch run` strips all `KEYLATCH_*` configuration variables from
the child process environment and injects only the variables needed for
credential access (gateway token + URL in gateway modes, or ephemeral tokens
in direct modes).

For CI and sandboxed environments, `--clean-env` reduces the child environment
to a minimal set:

```bash
# Minimal env: PATH, HOME, USER, SHELL, TERM, LANG, and injected credential vars
keylatch run openrouter --clean-env -- node script.js

# Preserve specific additional vars
keylatch run openrouter --clean-env --extra DATABASE_URL --extra REDIS_URL -- node script.js
```

## Security

- Secret values are never echoed to stdout/stderr
- LLM session detection blocks all direct value extraction
- All backends enforce encrypted-at-rest storage
- Audit log records every read, write, and injection — without values
- `List` operations zero-fill field values before returning
- Canary tokens are injected at test time to detect credential leaks
- Release artifacts are cosign-signed via GitHub Actions OIDC
- Heap dump protection: on Linux keylatchd scans process memory for residual deprecated patterns on startup; on macOS/Windows OS-level protection applies

For the vulnerability disclosure policy, SBOM, and artifact verification instructions, see [SECURITY.md](SECURITY.md).

## Desktop app

The Keylatch desktop app (macOS / Windows / Linux) wraps the same trusted runtime via a `keylatchd` sidecar. It provides a tray icon, approval inbox, first-run wizard, and one-click agent profile setup — no terminal required for day-to-day use.

Desktop builds are produced by goreleaser and are not part of the Docker image.

## Docker

```bash
# Build locally
docker build -t keylatch:dev .

# Run
docker run --rm -v ~/.keylatch:/root/.keylatch keylatch:dev doctor --json
```

The image uses `distroless/static:nonroot` at runtime (~2 MiB). No shell, no libc.

## Development

```bash
# Prerequisites: Go 1.25+, Bun 1.3.14+ (for web)

make build          # compile all packages
make test           # unit tests
make lint           # go vet
make security-grep  # static security check (S2-8)
make check          # full pre-commit suite

# Backend-specific E2E
make test-e2e-op    # requires KEYLATCH_E2E_OP=1 and op CLI
make test-e2e-bw    # requires Docker (starts Vaultwarden)

# Web UI
make build-web      # build SPA into web/dist/
make test-phase10   # Go + bun tests for Phase 10

# Canary leak detection
make test-canary
make test-canary-meta
```

## Documentation

### Getting Started
- [Getting Started](docs/getting-started.md)
- [Quickstart](docs/quickstart.md)
- [Installation](docs/installation.md)
- [CLI Reference](docs/cli-reference.md)

### Configuration
- [Configuration reference](docs/configuration.md)
- [CLI Environment Variables](docs/cli/environment.md)

### Runtime
- [Operating Modes](docs/operating-modes.md)
- [Proxy](docs/proxy.md)
- [Call](docs/call.md)
- [Scripting Guide](docs/scripting.md)

### Security
- [Verifying Releases](docs/verifying-releases.md)
- [Approval](docs/approval.md)
- [Architecture: Registry Signing](docs/architecture/registry-signing.md)

### Architecture
- [Architecture: Audit Log](docs/architecture/audit-log.md)

### Integrations

**Agent & language integration guides** — [docs/integration/README.md](docs/integration/README.md)

| Guide | Description |
|-------|-------------|
| [Shell (Bash/sh)](docs/integration/shell.md) | Inline capture, `keylatch run` wrapper, `.env` generation |
| [Python](docs/integration/python.md) | `subprocess.run`, context manager, SDK roadmap (v1.1.0) |
| [Node.js / TypeScript](docs/integration/node.md) | `execSync`, async exec, TypeScript types, `dotenv` interop |
| [Claude Code](docs/integration/agents/claude-code.md) | Hook installation, `CREDENTIALS_LLM_SESSION`, project setup |
| [Cursor](docs/integration/agents/cursor.md) | Auto-detection, PreToolUse hook, `.cursor/rules` patterns |
| [Gemini CLI](docs/integration/agents/gemini.md) | BeforeTool hook, `GEMINI_SESSION`, Google AI Studio |
| [Windsurf](docs/integration/agents/windsurf.md) | `CREDENTIALS_LLM_SESSION` shell rc pattern |
| [Generic agent](docs/integration/agents/generic.md) | Universal recipe, detection heuristics |
| [CI (GitHub Actions / GitLab)](docs/integration/ci.md) | File backend, vault secrets, log masking |

**Per-agent exfiltration guard guides** — [docs/integrations/](docs/integrations/)

- [Desktop App](docs/desktop-app.md)
- [Desktop Parity](docs/desktop-parity.md)
- [Telemetry](docs/telemetry.md)
- [Experimental Features](docs/experimental.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, the provider template workflow, and how to run the full test suite locally.

## License

Apache-2.0 — see [LICENSE](LICENSE).
