---
title: OpenCode
harness: opencode
---

# OpenCode

Support level: guard plus detection

```sh
keylatch agent install opencode
```

| What | Where |
|------|-------|
| Hook (`tool.execute.before`) | `~/.config/opencode/plugins/keylatch-guard.ts`, a plugin file |
| MCP server | `~/.config/opencode/opencode.json`, key `mcp` |
| Rules block | `~/.config/opencode/AGENTS.md` (a project's own: `AGENTS.md`) |

`$XDG_CONFIG_HOME/opencode` replaces `~/.config/opencode` when that variable is set.

The plugin passes every tool call to `keylatch guard hook --harness opencode` and throws, which blocks the call, when the guard denies, fails or is missing. It holds no patterns of its own; the Go guard decides. `keylatch agent install opencode --upgrade` rewrites it for a new binary path.

Detection: `OPENCODE` and the `opencode` process in a command's ancestry.

Formats last checked against: vendor documentation of 2026-10-09.
