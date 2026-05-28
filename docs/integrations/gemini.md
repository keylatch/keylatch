# Keylatch Integration — Gemini CLI

Blocks credential-exfiltration patterns in Gemini CLI sessions via a BeforeTool hook.

## Hook Mechanism

Gemini CLI's `hooks.BeforeTool` array in `~/.gemini/settings.json` (or `~/.config/gemini/settings.json`). Each hook reads a JSON event from stdin and outputs a JSON decision to stdout. The guard returns `{"decision":"deny","reason":"..."}` to block, `{"decision":"allow"}` to permit.

## Install

```bash
keylatch install-guard gemini
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

See also: `contrib/agent-guards/gemini/README.md`
