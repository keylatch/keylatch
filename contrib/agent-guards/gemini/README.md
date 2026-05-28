# Keylatch Guard — Gemini CLI

Blocks credential-exfiltration patterns from Gemini CLI tool calls via a BeforeTool hook.

## Hook Mechanism

Gemini CLI supports a `hooks.BeforeTool` array in `~/.gemini/settings.json` (or `~/.config/gemini/settings.json`). Each hook reads a JSON event from stdin and must output a JSON decision to stdout. The guard returns `{"decision":"deny","reason":"..."}` to block the tool call, or `{"decision":"allow"}` to permit it.

## Install

```bash
keylatch install-guard gemini
```

Or manually:

```bash
bash contrib/agent-guards/gemini/install.sh
```

This copies the guard script to `~/.keylatch/guards/gemini-guard.sh` and merges the hook entry into `~/.gemini/settings.json`.

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
