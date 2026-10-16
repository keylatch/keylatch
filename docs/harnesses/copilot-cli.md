---
title: GitHub Copilot CLI
harness: copilot-cli
---

# GitHub Copilot CLI

Support level: guard plus detection

```sh
keylatch agent install copilot-cli
```

| What | Where |
|------|-------|
| Hook (`preToolUse`) | `~/.copilot/hooks/keylatch-guard.json` (a project's own: `.github/hooks/keylatch-guard.json`) |
| MCP server | `~/.copilot/mcp-config.json` |
| Rules block | `~/.copilot/copilot-instructions.md` (a project's own: `.github/copilot-instructions.md`) |

`$COPILOT_HOME` replaces `~/.copilot` when it is set.

The hook runs `keylatch guard hook --harness copilot-cli`; a denial is `{"permissionDecision":"deny"}` with exit status 2. Copilot has no operating-system sandbox of its own, so Keylatch's contained tier matters most here.

The Copilot cloud coding agent runs on GitHub's runners, where the local daemon is unreachable, and is not covered.

Detection: the `copilot` process in a command's ancestry; Copilot sets no environment marker.

Formats last checked against: vendor documentation of 2026-10-09.
