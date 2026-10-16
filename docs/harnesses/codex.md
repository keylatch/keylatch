---
title: Codex CLI
harness: codex
---

# Codex CLI

Support level: guard plus detection

```sh
keylatch agent install codex
```

| What | Where |
|------|-------|
| Hook (`PreToolUse`) | `~/.codex/hooks.json`, an object keyed by event |
| MCP server | `~/.codex/config.toml`, table `[mcp_servers.keylatch]` |
| Rules block | `~/.codex/AGENTS.md` (a project's own: `AGENTS.md`) |

`$CODEX_HOME` replaces `~/.codex` when it is set.

The hook runs `keylatch guard hook --harness codex` for the shell tool and denies with exit status 2 and `hookSpecificOutput.permissionDecision`. The `config.toml` change is one block between `# >>> keylatch >>>` and `# <<< keylatch <<<`; everything else in the file, comments included, stays byte for byte. A `[mcp_servers.keylatch]` table of your own outside the block makes the install stop instead of overwriting it.

Codex runs a non-managed hook only after you review it: open `/hooks` in Codex and trust the Keylatch hook.

Detection: `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED`, and the `codex` process in a command's ancestry.

Formats last checked against: vendor documentation of 2026-10-09.
