# Keylatch Integration — GitHub Copilot CLI

Blocks credential-exfiltration patterns in Copilot CLI sessions via a shell wrapper fallback.

## Hook Mechanism

The native Copilot CLI hook config path is unconfirmed. The guard is installed as a shell function wrapper. For native hook support, verify current docs at keylatch.dev/integrations/copilot.

## Install

```bash
keylatch install-guard copilot
```

This installs a shell wrapper in `~/.zshrc` / `~/.bashrc` that intercepts copilot invocations.

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

See also: `contrib/agent-guards/copilot/README.md`
