# Keylatch Guard — Cursor

Blocks credential-exfiltration patterns from Cursor AI tool calls via a PreToolUse hook.

## Hook Mechanism

Cursor supports a `hooks.PreToolUse` array in `~/.cursor/settings.json`. Each hook entry specifies a shell command executed before every tool invocation. The guard exits non-zero to block the tool call.

## Install

```bash
keylatch install-guard cursor
```

Or manually:

```bash
bash contrib/agent-guards/cursor/install.sh
```

This copies the guard script to `~/.keylatch/guards/cursor-guard.sh` and merges the hook entry into `~/.cursor/settings.json`.

## What It Blocks

- `keylatch get` (without `--masked`)
- `security find-password` / `security find-generic-password`
- `op read`
- `bw get`
- `cat ~/.keylatch/config.yaml`
- Direct reads of `~/.keylatch/keylatch.keychain-db`

## Verify

```bash
keylatch doctor
```
