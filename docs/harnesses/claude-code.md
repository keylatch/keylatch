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

Use `keylatch agent install claude-code --sandbox --dry-run` to preview the sandbox changes, then omit `--dry-run` to apply them. This component enables the sandbox and filesystem isolation, removes Keylatch exclusions, disables unsandboxed fallback, denies reads of Keylatch state and OS keyrings, and adds daemon sockets. It is separate from the default guard/MCP/rules installation. On Linux, [the host runtime cannot filter Unix sockets by path](https://github.com/anthropics/sandbox-runtime#network-configuration), so this enables `allowAllUnixSockets`; macOS uses the individual socket list. Uninstalling `--sandbox` removes the Keylatch socket entries and turns the Linux broad socket allowance off, but retains the state read denies and disabled unsandboxed fallback.

Register a remote bearer-authenticated server with `keylatch agent install claude-code --mcp --mcp-proxy remote-docs=https://mcp.example.com/mcp`. The configuration stores no credential. For OAuth, configure the server command with the `mcp proxy --oauth` options in the [CLI reference](../cli-reference.md#keylatch-mcp-proxy).

The `SANDBOX` column in `doctor --agents` checks exclusions: `ok` means no matching exclusions were found, `excluded` names them, and `unknown` means some settings could not be read. It does not certify sandbox activation or socket reachability from a running Claude Code session.

Detection: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, and the `claude` process in a command's ancestry.

Formats last checked against: vendor documentation of 2026-10-09; the nightly drift workflow re-checks them against the published release.
