---
title: Claude Code
harness: claude-code
---

# Claude Code

Support level: guard plus detection

```sh
keylatch agent install claude-code
```

| What | Where |
|------|-------|
| Hook (`PreToolUse`) | `~/.claude/settings.json` (a project's own: `.claude/settings.json`) |
| MCP server | `~/.claude.json`; inside `$CLAUDE_CONFIG_DIR` when that is set |
| Rules block | `~/.claude/CLAUDE.md` (a project's own: `CLAUDE.md`) |

The hook runs `keylatch guard hook --harness claude-code` for every tool call. It denies a read of a credential location, a secret-manager call, an environment dump and a change to the harness's own settings, with exit status 2 and `hookSpecificOutput.permissionDecision`. A guard that cannot parse its input denies.

`--config-dir <dir>` installs into further Claude Code configuration directories. `--upgrade` rewrites an installed entry (new binary path, matcher, timeout) and replaces the shell-script guard of earlier releases. Every file is saved as `<name>.keylatch.bak` first.

Claude Code starts hooks and MCP servers outside its sandbox; do not list `keylatch` in `excludedCommands`, and set `allowUnsandboxedCommands: false`. `keylatch doctor --agents` reports the state.

Detection: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, and the `claude` process in a command's ancestry.

Formats last checked against: vendor documentation of 2026-10-09; the nightly drift workflow re-checks them against the published release.
