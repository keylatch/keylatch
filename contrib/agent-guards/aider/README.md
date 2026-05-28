# Keylatch Guard — Aider

Blocks credential-exfiltration patterns from Aider tool calls via Aider's `pre-tool-use-hook`.

## Hook Mechanism

Aider supports a `pre-tool-use-hook` key in `~/.aider.conf.yml`. The value is a shell command invoked before every tool call. The guard exits non-zero to block the call.

## Install

```bash
keylatch install-guard aider
```

Or manually:

```bash
bash contrib/agent-guards/aider/install.sh
```

This copies the guard script to `~/.keylatch/guards/aider-guard.sh` and appends the hook configuration to `~/.aider.conf.yml`.

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
