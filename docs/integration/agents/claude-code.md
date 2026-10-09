---
title: Claude Code Integration
description: Using Keylatch with Claude Code — hook installation, CREDENTIALS_LLM_SESSION, project setup.
---

# Claude Code Integration

Keylatch integrates with Claude Code at two levels:

1. **Auto-detection** — Keylatch detects active Claude Code sessions via the `CLAUDECODE` and `CLAUDE_CODE_ENTRYPOINT` environment variables and blocks raw credential access automatically.
2. **Exfiltration guard** — A `PreToolUse` hook in `.claude/settings.json` blocks credential exfiltration at the agent framework level (Layer 2).

## Quick start

```bash
# Install the exfiltration guard (global — all Claude Code sessions)
keylatch install-guard claude-code

# Or per-project (installs into .claude/settings.json in current directory)
keylatch install-guard claude-code --project

# Verify
keylatch doctor
```

## How detection works

Claude Code sets `CLAUDECODE=1` (and `CLAUDE_CODE_ENTRYPOINT`) in the shells it spawns. Keylatch reads these signals and activates LLM-session mode automatically. The agent can unset these variables, so detection is a convenience, not a security boundary. In this mode:

- `keylatch get` — blocked, exit code 2 (SecurityBlock)
- `keylatch run` — allowed for all runtime modes
- `keylatch ui` — scope locked to status-only
- Raw credential values are never returned to the agent process

You can also manually declare an LLM session for any tool that does not set its own env var:

```bash
export CREDENTIALS_LLM_SESSION=claude-code
```

This activates the same guards without requiring the `CLAUDECODE` var.

## `.claude/settings.json` hook pattern

The `keylatch install-guard claude-code` command writes a `PreToolUse` hook to `~/.claude/settings.json` (global) or `.claude/settings.json` (project-local with `--project`).

After installation, the settings file contains:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.keylatch/hooks/block-keylatch-exfiltration.sh"
          }
        ]
      }
    ]
  }
}
```

The hook script exits non-zero when it detects credential exfiltration patterns (e.g. `keylatch get`, `security find-generic-password`, `op read`, `cat .env`), causing Claude Code to block the tool call before it executes.

## Never exclude keylatch from the sandbox

Claude Code's sandbox can exempt commands through `sandbox.excludedCommands`. Do not list `keylatch` there, in user, project or local settings.

A command in `excludedCommands` runs outside the sandbox, and so does everything it launches. With `keylatch run:*` or `keylatch launch:*` excluded, `keylatch run <connection> -- pnpm test` starts `pnpm test`, and every test, build script and `postinstall` hook it triggers, as your user with no filesystem or network limits. That process can read `~/.keylatch`, `~/.ssh`, browser profiles and every other credential store. The injected credential is the smallest part of what is exposed, and the exfiltration guard does not help: it blocks known credential-access patterns, and `pnpm test` is not one.

Remove the entries:

```json
{
  "sandbox": {
    "excludedCommands": ["docker:*"]
  }
}
```

The example shows a list with the `keylatch` entries removed and an unrelated entry (`docker:*`) kept. Agents use `keylatch call`, which has no child process. Run `keylatch run` or `keylatch launch` yourself in a terminal (or with `! keylatch run <connection> -- <command>` from the Claude Code prompt).

`keylatch doctor` reads the managed settings, the user settings (`~/.claude/settings.json`, or `$CLAUDE_CONFIG_DIR/settings.json`), and the project (`.claude/settings.json`) and local (`.claude/settings.local.json`) settings of `$CLAUDE_PROJECT_DIR` or the working directory. Managed settings are `managed-settings.json` plus `managed-settings.d/*.json` in `/etc/claude-code` (Linux), `/Library/Application Support/ClaudeCode` (macOS) or `C:\Program Files\ClaudeCode` (Windows); doctor tells you to ask the administrator to change those.

The `host.sandbox.keylatch_excluded` check fails unless the excluded entry is a literal subcommand that never starts a child process (such as `call`). Entries that can reach `keylatch run` or `keylatch launch` fail: the bare `keylatch`, `keylatch:*`, `keylatch run:*`, `keylatch launch:*`, leading global flags (`keylatch --quiet run:*`), wildcards in the subcommand (`keylatch r*`), and quoted or absolute paths, including Windows `.exe` paths. Entries that exclude only other subcommands produce a warning. The detail names the project directory and the files checked, and any file it could not read.

## `CREDENTIALS_LLM_SESSION` signal

`CREDENTIALS_LLM_SESSION` is the generic LLM session signal. Setting it to any non-empty value activates all Keylatch LLM-session guards, regardless of which agent is running.

For Claude Code running in a context where `CLAUDECODE` is not automatically set (e.g. custom launchers or CI):

```bash
# ~/.zshrc or ~/.bashrc
export CREDENTIALS_LLM_SESSION=claude-code
```

Keylatch treats any non-empty value as a positive signal — the value is used for logging purposes only.

## Example project setup

```bash
# 1. Bootstrap Keylatch
keylatch setup

# 2. Connect your API provider
keylatch connect openrouter

# 3. Install the exfiltration guard for this project
cd /path/to/your/project
keylatch install-guard claude-code --project

# 4. Start the gateway in the background
keylatch gateway up --detach

# 5. Mint a scoped token for Claude Code
keylatch gateway token create claude-code --allow openrouter.chat --ttl 4h

# 6. Verify everything is set up
keylatch doctor
```

## Running scripts from Claude Code

When Claude Code needs to run a script that calls an API, use `keylatch run` as the outer wrapper:

```bash
# Claude Code invokes this — not raw credential access
keylatch run --clean-env --runtime gateway_typed openrouter -- node my-script.js
```

The raw credential stays in the vault. The script receives a short-lived gateway token.

## Checking guard status

```bash
keylatch doctor
# Look for: [ok  ] hook.preToolUse: keylatch preToolUse hook detected
```

## Related

- [docs/integrations/claude-code.md](../../integrations/claude-code.md) — full agent-guard guide
- [docs/integration/agents/generic.md](generic.md) — universal detection recipe
- [docs/integration/README.md](../README.md) — integration guide index
