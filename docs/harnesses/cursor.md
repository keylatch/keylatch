---
title: Cursor
harness: cursor
---

# Cursor

Support level: guard plus detection

```sh
keylatch agent install cursor
```

Use `keylatch agent install cursor --mcp --mcp-proxy remote-docs=https://mcp.example.com/mcp` to register a remote server through Keylatch. Cursor receives only the connection name and URL, not a bearer token. OAuth server commands use the additional `mcp proxy --oauth` options described in the [CLI reference](../cli-reference.md#keylatch-mcp-proxy). The standard Keylatch MCP server also provides `keylatch_explain` for a policy-only run explanation.

| What | Where |
|------|-------|
| Hooks (`beforeShellExecution`, `beforeReadFile`, `beforeMCPExecution`) | `~/.cursor/hooks.json` (a project's own: `.cursor/hooks.json`) |
| MCP server | `~/.cursor/mcp.json` |
| Rules block | a project's `.cursor/rules/keylatch.mdc` (Cursor has no user-level rules file); use `--project` |

Each hook runs `keylatch guard hook --harness cursor` with the payload as JSON on stdin and `failClosed`: a hook that does not run blocks the action. A denial is exit status 2 plus `{"permission":"deny"}`.

Cursor does not currently enforce a `beforeReadFile` deny for agent reads, so that hook is defence in depth; add the patterns `keylatch agent install cursor` prints to each project's `.cursorignore`. The install also removes the guard entry an earlier release put in `~/.cursor/settings.json`, which Cursor does not read for hooks.

Background agents run where the local daemon is unreachable and are not covered.

Detection: `CURSOR_AGENT`, `CURSOR_TRACE_ID`, and the `cursor-agent` process in a command's ancestry.

Formats last checked against: vendor documentation of 2026-10-09.
