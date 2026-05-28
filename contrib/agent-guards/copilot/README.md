# Keylatch Guard — GitHub Copilot CLI

Blocks credential-exfiltration patterns from GitHub Copilot CLI tool calls via a shell wrapper fallback.

## Hook Mechanism

The native Copilot CLI hook config path is unconfirmed (the original `gh copilot` extension is retired). The guard is installed as a shell function wrapper that intercepts copilot invocations at the shell level.

For native hook support, verify current docs at keylatch.dev/integrations/copilot.

## Install

```bash
keylatch install-guard copilot
```

Or manually:

```bash
bash contrib/agent-guards/copilot/install.sh
```

This copies the guard script to `~/.keylatch/guards/copilot-guard.sh` and appends a wrapper function to `~/.zshrc` / `~/.bashrc`.

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
