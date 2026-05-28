# Keylatch Integration — Codex CLI

Blocks credential-exfiltration patterns in Codex CLI sessions via a PreToolUse hook.

## Hook Mechanism

Codex CLI's `hooks.PreToolUse` array in `~/.codex/hooks.json`. Each hook reads a JSON event from stdin and outputs a JSON decision to stdout. The guard returns `{"decision":"block","reason":"..."}` to block the tool call.

## Install

```bash
keylatch install-guard codex
```

## What It Blocks

- `keylatch get` / `keylatch secret get`
- `security find-password` / `security find-generic-password`
- `op read`, `bw get`
- `cat ~/.keylatch/config.yaml`
- Direct access to `~/.keylatch/keylatch.keychain-db`

## Verify

```bash
keylatch doctor
```

See also: `contrib/agent-guards/codex/README.md`
