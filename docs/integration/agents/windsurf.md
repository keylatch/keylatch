---
title: Windsurf Integration
description: Using Keylatch with Windsurf — pre_run_command hook and CREDENTIALS_LLM_SESSION shell rc pattern.
---

# Windsurf Integration

Windsurf does not set a unique environment variable when its integrated terminal is active, so Keylatch uses the generic `CREDENTIALS_LLM_SESSION` signal set in your shell rc file. Cascade also has a `pre_run_command` hook, which `keylatch install-guard windsurf` uses to block credential-exfiltration commands before they run.

## Quick start

```bash
# Install the pre_run_command hook
keylatch install-guard windsurf
# Hook written to: ~/.codeium/windsurf/hooks.json
```

The hook blocks a denied command with exit 2 (the only blocking signal Cascade documents). Then set `CREDENTIALS_LLM_SESSION=windsurf` in your shell configuration so the Layer 1 guard applies too.

## Shell rc configuration

Add this to your shell configuration file and restart your terminal (or reload the shell rc):

**zsh / bash:**

```bash
export CREDENTIALS_LLM_SESSION=windsurf
```

**fish:**

```fish
set -Ux CREDENTIALS_LLM_SESSION windsurf
```

**PowerShell:**

```powershell
[Environment]::SetEnvironmentVariable('CREDENTIALS_LLM_SESSION','windsurf','User')
```

## What this does

Setting `CREDENTIALS_LLM_SESSION=windsurf` activates Keylatch's Layer 1 LLM-session guard in all terminals. When active:

- `keylatch get` — blocked, exit code 2 (SecurityBlock)
- `keylatch run` — allowed for all runtime modes
- Raw credential values are never returned to the process

This guard is active whenever `CREDENTIALS_LLM_SESSION` is non-empty, so it protects the Windsurf integrated terminal from credential exfiltration by any script or tool running in that context.

## Layer 2 hook

The installer registers `pre_run_command` and `pre_read_code`; a denied read or command exits 2. The read hook also denies a directory that contains a protected location. Cascade reads `hooks.json` from `~/.codeium/windsurf/hooks.json`, `.devin/hooks.json` in the workspace and the system file. Hooks do not run in Restricted Mode. See [docs/integrations/windsurf.md](../../integrations/windsurf.md) for the entry the installer writes.

## Using Keylatch inside Windsurf

Store credentials and use `keylatch run` for any subprocess that needs API access:

```bash
# Store a provider credential
keylatch connect openrouter

# Run a script with credentials injected
keylatch run --clean-env --runtime gateway_typed openrouter -- node my-script.js
```

## Verifying the guard is active

```bash
# From a terminal where CREDENTIALS_LLM_SESSION is set:
keylatch doctor --category environment
# Look for: [warn] llm.session: llm_session=true reasons=[CREDENTIALS_LLM_SESSION]

# Confirm keylatch get is blocked:
keylatch get openrouter
# Expected: Error (SecurityBlock), exit code 2
```

## Related

- [docs/integrations/windsurf.md](../../integrations/windsurf.md) — full Windsurf guard guide
- [docs/integration/agents/generic.md](generic.md) — universal detection recipe
- [docs/integration/README.md](../README.md) — integration guide index
