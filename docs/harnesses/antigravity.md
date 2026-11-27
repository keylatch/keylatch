---
title: Antigravity
harness: antigravity
---

# Antigravity

Support level: guard plus detection

```sh
keylatch agent install antigravity
```

| What | Where |
|------|-------|
| Hook (`PreToolUse`) | `~/.gemini/config/hooks.json`, the hook set `keylatch-guard` (a project's own: `.agents/hooks.json`) |
| MCP server | `~/.gemini/antigravity/mcp_config.json` |
| Rules block | `~/.gemini/GEMINI.md` (a project's own: `.agents/rules/keylatch.md`) |

The hook runs `keylatch guard hook --harness antigravity`. Antigravity documents decisions as JSON on standard output only, so a denial is `{"decision":"deny"}` with exit status 0.

Status: the hook and MCP file locations and payload shape come from the vendor documentation and are not yet confirmed against a release. One report says the IDE's deny hook does not fire; the drift workflow does not run Antigravity, so check `keylatch doctor --agents` and try a denied command after installing.

Detection: Antigravity sets no environment marker Keylatch knows of.
