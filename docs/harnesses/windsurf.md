---
title: Windsurf
harness: windsurf
---

# Windsurf

Support level: guard plus detection

```sh
keylatch agent install windsurf
```

| What | Where |
|------|-------|
| Hooks (`pre_run_command`, `pre_read_code`, `pre_write_code`, `pre_mcp_tool_use`) | `~/.codeium/windsurf/hooks.json` (a project's own: `.windsurf/hooks.json`) |
| MCP server | `~/.codeium/windsurf/mcp_config.json` |
| Rules block | `~/.codeium/windsurf/memories/global_rules.md` (a project's own: `.windsurf/rules/keylatch.md`) |

Each hook runs `keylatch guard hook --harness windsurf`; a hook that exits with status 2 blocks the action, and the reason goes to standard error.

Status: the file locations and payload shape come from the vendor documentation and are not yet confirmed against a release. Windsurf has no sandbox of its own that Keylatch knows of.

Detection: the `windsurf` process in a command's ancestry.
