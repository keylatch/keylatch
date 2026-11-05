---
title: Gemini CLI
harness: gemini-cli
---

# Gemini CLI

Support level: guard plus detection

```sh
keylatch agent install gemini-cli
```

| What | Where |
|------|-------|
| Hook (`BeforeTool`) | `~/.gemini/settings.json`, matcher groups (a project's own: `.gemini/settings.json`) |
| MCP server | `~/.gemini/settings.json`, key `mcpServers` |
| Rules block | `~/.gemini/GEMINI.md` (a project's own: `GEMINI.md`) |

`$GEMINI_CLI_HOME` replaces the home directory the `.gemini` directory hangs from.

The hook runs `keylatch guard hook --harness gemini-cli` for the shell and every file tool and denies with `{"decision":"deny"}` and exit status 2. Gemini reads only JSON from a hook's standard output, so the guard prints nothing else; for an allowed call it prints `{"decision":"allow"}`.

The merge needs strict JSON. A `settings.json` with comments or trailing commas is refused with the file named, not rewritten.

Detection: `GEMINI_CLI` and the `gemini` process in a command's ancestry.

Formats last checked against: vendor documentation of 2026-10-09.
