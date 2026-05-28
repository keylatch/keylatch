# Keylatch Guard — Codex CLI

Blocks credential-exfiltration patterns from Codex CLI tool calls via a PreToolUse hook.

## Hook Mechanism

Codex CLI supports a `hooks.PreToolUse` array in `~/.codex/hooks.json`. Each hook reads a JSON event from stdin and outputs a JSON decision to stdout. The guard returns `{"decision":"block","reason":"..."}` to block the tool call.

## Install

```bash
keylatch install-guard codex
```

Or manually:

```bash
bash contrib/agent-guards/codex/install.sh
```

This copies the guard script to `~/.keylatch/guards/codex-guard.sh` and merges the hook entry into `~/.codex/hooks.json`.

## What It Blocks

- `keylatch get` / `keylatch secret get`
- `security find-password` / `security find-generic-password`
- `op read`
- `bw get`
- `cat ~/.keylatch/config.yaml`
- Direct access to `~/.keylatch/keylatch.keychain-db`

## Verify

```bash
keylatch doctor
```
