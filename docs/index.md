---
title: Keylatch
description: Zero-trust credential vault CLI — give AI tools session tokens, not raw API keys.
---

# Keylatch

Keylatch is a zero-trust credential broker for AI agents. It stores your API keys in an encrypted backend and gives AI tools short-lived session tokens — never the raw credentials.

## Why Keylatch

| Problem | Keylatch solution |
|---------|------------------|
| AI agents can read raw API keys from the environment | LLM session detection blocks direct access; keys never reach the agent |
| `.env` files are plaintext on disk | All backends encrypt credentials at rest |
| No audit trail for AI tool credential use | Tamper-evident HMAC-chained audit log — value-free |
| Hard to rotate keys across many tools | One `keylatch connect` command updates all tools using that provider |

## Quick start

```bash
# Install
brew install keylatch/tap/keylatch

# Set up (guided wizard)
keylatch setup

# Or scriptable setup
keylatch bootstrap
keylatch connect openrouter

# Preview what would be injected
keylatch run openrouter --dry-run -- my-ai-tool

# Run a command with injected credentials
keylatch run openrouter -- my-ai-tool
```

---

## Documentation

### Getting Started

| Page | Description |
|------|-------------|
| [Installation](./installation.md) | Homebrew, Scoop, manual tarball, Linux, Docker |
| [Quickstart](./quickstart.md) | From zero to first verified run in 5 minutes |
| [Getting Started](./getting-started.md) | Guided walkthrough with concepts |
| [CLI Reference](./cli-reference.md) | Every command, flag, and exit code |

### Configuration

| Page | Description |
|------|-------------|
| [Configuration](./configuration.md) | Full reference for `config.json` keys |
| [CLI Environment Variables](./cli/environment.md) | Every `KEYLATCH_*` variable — purpose, sensitivity, child-env policy |

### Runtime

| Page | Description |
|------|-------------|
| [Operating Modes](./operating-modes.md) | `standard`, `telemetry`, `canary`, `custom` — controlling subsystems |
| [Proxy](./proxy.md) | CONNECT proxy for tools that only speak `HTTP_PROXY` |
| [Call](./call.md) | Dispatch single provider actions with `keylatch call` |
| [Scripting Guide](./scripting.md) | Python, Bash, and Node.js examples using `keylatch run` as a secure envelope |

### Security

| Page | Description |
|------|-------------|
| [Verifying Releases](./verifying-releases.md) | Cosign verification, SLSA provenance, SBOM |
| [Approval](./approval.md) | Approval inbox — reviewing and granting pending requests |
| [Architecture: Registry Signing](./architecture/registry-signing.md) | How provider templates are signed and verified |

### Architecture

| Page | Description |
|------|-------------|
| [Architecture: Audit Log](./architecture/audit-log.md) | HMAC-chained, tamper-evident audit log design |

### Integration Guides

How to integrate Keylatch with agents, languages, and CI systems. Start at the [Integration Guide index](./integration/README.md).

| Page | Description |
|------|-------------|
| [Integration Guides](./integration/README.md) | Quick-start matrix, flow diagram, links to all guides |
| [Shell (Bash/sh)](./integration/shell.md) | `keylatch run` wrapper, inline capture, `.env` generation |
| [Python](./integration/python.md) | `subprocess.run`, context manager, SDK roadmap |
| [Node.js / TypeScript](./integration/node.md) | `execSync`, async exec, TypeScript types, `dotenv` interop |
| [CI (GitHub Actions / GitLab)](./integration/ci.md) | File backend in CI, vault secrets, log masking |
| [Claude Code agent guide](./integration/agents/claude-code.md) | Hooks, detection, `CREDENTIALS_LLM_SESSION` |
| [Cursor agent guide](./integration/agents/cursor.md) | Auto-detection, PreToolUse hook |
| [Gemini CLI agent guide](./integration/agents/gemini.md) | `GEMINI_SESSION`, BeforeTool hook |
| [Windsurf agent guide](./integration/agents/windsurf.md) | Shell rc, `CREDENTIALS_LLM_SESSION` |
| [Generic agent guide](./integration/agents/generic.md) | Universal recipe, detection heuristics |

### Integrations (platform)

| Page | Description |
|------|-------------|
| [Desktop App](./desktop-app.md) | macOS / Windows desktop app — tray icon, approval inbox, first-run wizard |
| [Desktop Parity](./desktop-parity.md) | Feature parity matrix between CLI and desktop app |
| [Telemetry](./telemetry.md) | What is collected, opt-in/opt-out, and data policy |
| [Experimental Features](./experimental.md) | Features behind the experimental gate |
