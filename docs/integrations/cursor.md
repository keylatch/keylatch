# Keylatch Integration — Cursor

Blocks credential-exfiltration patterns in Cursor AI sessions via a PreToolUse hook.

## Hook Mechanism

Cursor's `hooks.PreToolUse` array in `~/.cursor/settings.json`. Each hook is a shell command invoked before every tool call. The guard exits non-zero to block the call.

## Install

```bash
keylatch install-guard cursor
```

## What It Blocks

- `keylatch get` (without `--masked`)
- `security find-password` / `security find-generic-password`
- `op read`, `bw get`
- `cat ~/.keylatch/config.yaml`
- Direct reads of `~/.keylatch/keylatch.keychain-db`

## Verify

```bash
keylatch doctor
```

See also: `contrib/agent-guards/cursor/README.md`
