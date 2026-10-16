---
title: Agent harnesses
---

# Agent harnesses

`keylatch agent install <harness>` writes the Keylatch guard hook, the MCP server and a rules block into a harness's own configuration by structured merge: every other key, hook and comment stays, and each file is saved as `<name>.keylatch.bak` first. `--dry-run` prints the diff, `--upgrade` refreshes installed entries, `--all` installs every harness found on this machine, `--project` writes the current project's files, and `--guard`, `--mcp` and `--rules` pick parts. `keylatch doctor --agents` reports what is in place. `keylatch install-guard` is the older spelling and prints a deprecation notice.

| Harness | Support level | Hook | Page |
|---------|---------------|------|------|
| Claude Code | guard plus detection | `PreToolUse` in `settings.json` | [claude-code](claude-code.md) |
| Codex CLI | guard plus detection | `PreToolUse` in `hooks.json` | [codex](codex.md) |
| Cursor | guard plus detection | `beforeShellExecution`, `beforeReadFile`, `beforeMCPExecution` in `hooks.json` | [cursor](cursor.md) |
| Gemini CLI | guard plus detection | `BeforeTool` in `settings.json` | [gemini-cli](gemini-cli.md) |
| OpenCode | guard plus detection | `tool.execute.before` plugin | [opencode](opencode.md) |
| GitHub Copilot CLI | guard plus detection | `preToolUse` in `hooks/keylatch-guard.json` | [copilot-cli](copilot-cli.md) |
| Antigravity | guard plus detection | `PreToolUse` in `config/hooks.json` | [antigravity](antigravity.md) |
| Windsurf | guard plus detection | `pre_run_command` and others in `hooks.json` | [windsurf](windsurf.md) |
| Aider | launch only | none | [aider](aider.md) |
| Goose | launch only | none | [goose](goose.md) |

Support levels: **guard plus detection** installs a hook that runs the Keylatch guard and recognizes the harness's sessions; **detection only** recognizes sessions and serves the MCP tools but has no hook to install; **launch only** starts the harness through `keylatch launch`.

Every hook runs `keylatch guard hook --harness <id>`, which reads the harness's own payload and answers in its deny contract. Hooks are one layer: a harness can bypass or lack them, so the broker daemon, the placeholder proxy and the contained tier hold the line for a process that ignores its hook.

The file formats are taken from vendor documentation. The `harness-drift` workflow installs the latest published Claude Code, Codex, Gemini CLI and OpenCode every night, runs `keylatch agent install --dry-run` against them and opens an issue when a harness stops accepting the generated configuration.
