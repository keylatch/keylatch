# Keylatch Integration — Aider

Blocks credential-exfiltration patterns in Aider sessions via the `pre-tool-use-hook` config.

## Hook Mechanism

Aider's `pre-tool-use-hook` key in `~/.aider.conf.yml`. The value is a shell command invoked before every tool call. The guard exits non-zero to block the call.

## Install

```bash
keylatch install-guard aider
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

See also: `contrib/agent-guards/aider/README.md`
