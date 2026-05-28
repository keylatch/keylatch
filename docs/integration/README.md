---
title: Integration Guides
description: One-page orientation for integrating Keylatch with agents, languages, and CI systems.
---

# Keylatch Integration Guides

Keylatch sits between your AI agent (or script) and the credential store. Your agent never sees the raw API key — it receives a short-lived gateway token scoped to a specific provider.

## Architecture overview

```
 ┌──────────────────────────────────────────────────────────────┐
 │  Encrypted vault (Keychain / 1Password / Bitwarden / file)   │
 │    ↓                                                         │
 │  Keylatch core (policy engine + audit log)                   │
 │    ↓                                                         │
 │  keylatch run — wraps your command as a child process        │
 │    ↓  injects: KEYLATCH_GATEWAY_TOKEN + KEYLATCH_GATEWAY_URL │
 │  Your script / MCP server / agent tool                       │
 │    ↓  calls: gateway endpoint (not raw provider API)         │
 │  Local Keylatch gateway → provider API                       │
 └──────────────────────────────────────────────────────────────┘
```

The raw credential never leaves the vault. The agent process receives a short-lived token that expires with the session. Every access is recorded in the tamper-evident audit log.

---

## Quick-start matrix

| | Claude Code | Cursor | Gemini CLI | Windsurf | Generic |
|---|---|---|---|---|---|
| **Shell** | [shell.md](shell.md) | [shell.md](shell.md) | [shell.md](shell.md) | [shell.md](shell.md) | [shell.md](shell.md) |
| **Python** | [python.md](python.md) | [python.md](python.md) | [python.md](python.md) | [python.md](python.md) | [python.md](python.md) |
| **Node.js** | [node.md](node.md) | [node.md](node.md) | [node.md](node.md) | [node.md](node.md) | [node.md](node.md) |
| **Agent guide** | [agents/claude-code.md](agents/claude-code.md) | [agents/cursor.md](agents/cursor.md) | [agents/gemini.md](agents/gemini.md) | [agents/windsurf.md](agents/windsurf.md) | [agents/generic.md](agents/generic.md) |
| **CI** | [ci.md](ci.md) | [ci.md](ci.md) | [ci.md](ci.md) | [ci.md](ci.md) | [ci.md](ci.md) |

---

## Canonical one-liner

```bash
# Wrap any command with Keylatch credential injection
keylatch run --clean-env --runtime gateway_typed <provider> -- <command>

# Example: call an API from a bash script
keylatch run --clean-env openrouter -- bash my_script.sh

# Example: call an action directly (dispatches a named provider action)
keylatch call openrouter list-models
```

---

## Language guides

| Guide | Description |
|-------|-------------|
| [Shell (Bash/sh)](shell.md) | Three patterns: `keylatch run` wrapper, inline capture, `.env` generation |
| [Python](python.md) | `subprocess.run`, context manager, SDK roadmap (v1.1.0) |
| [Node.js / TypeScript](node.md) | `execSync`, async `child_process.exec`, TypeScript types, `dotenv` interop |

---

## Agent guides

| Guide | Agent | Detection signal |
|-------|-------|-----------------|
| [Claude Code](agents/claude-code.md) | Claude Code | `CLAUDE_CODE` env var |
| [Cursor](agents/cursor.md) | Cursor | `CURSOR_SESSION` env var |
| [Gemini CLI](agents/gemini.md) | Gemini CLI | `GEMINI_SESSION` env var |
| [Windsurf](agents/windsurf.md) | Windsurf | `CREDENTIALS_LLM_SESSION=windsurf` (manual) |
| [Generic](agents/generic.md) | Any agent | `CREDENTIALS_LLM_SESSION` fallback |

---

## CI / CD guides

| Guide | Description |
|-------|-------------|
| [CI Integration](ci.md) | GitHub Actions and GitLab CI patterns |

---

## Example scripts

| Script | What it does |
|--------|-------------|
| [examples/python/fetch_data.py](examples/python/fetch_data.py) | Fetch models from gateway (Python) |
| [examples/node/fetchData.ts](examples/node/fetchData.ts) | Fetch models from gateway (TypeScript) |
| [examples/agents/detect_session.sh](examples/agents/detect_session.sh) | Heuristic agent session detection |
| [examples/ci/github-actions.yml](examples/ci/github-actions.yml) | Full GitHub Actions workflow |
| [examples/ci/gitlab-ci.yml](examples/ci/gitlab-ci.yml) | Full GitLab CI pipeline |

---

## Related docs

- [docs/scripting.md](../scripting.md) — deeper scripting guide for Python, Bash, Node
- [docs/cli/environment.md](../cli/environment.md) — all `KEYLATCH_*` env vars
- [docs/cli-reference.md](../cli-reference.md) — full CLI reference
- [docs/integrations/](../integrations/) — per-agent exfiltration guard guides
