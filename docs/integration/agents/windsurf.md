---
title: Windsurf Integration
description: Using Keylatch with Windsurf — CREDENTIALS_LLM_SESSION shell rc pattern.
---

# Windsurf Integration

Windsurf does not set a unique environment variable when its integrated terminal is active, and does not have a hook API for pre-tool-use guards. Keylatch integrates with Windsurf using the generic `CREDENTIALS_LLM_SESSION` signal set in your shell rc file.

## Quick start

```bash
# Get setup instructions
keylatch install-guard windsurf
```

This command prints shell-rc instructions — it does not write any files. Follow the printed instructions to set `CREDENTIALS_LLM_SESSION=windsurf` in your shell configuration.

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

## Limitation: no Layer 2 hook

Windsurf does not currently expose a hook API for pre-tool-use guards. Layer 1 (the `CREDENTIALS_LLM_SESSION` guard in the Keylatch binary) is the only automated protection available.

If Windsurf adds hook support in the future, Keylatch will add `keylatch install-guard windsurf` support. Track the issue at [keylatch.dev/integrations/windsurf](https://keylatch.dev/integrations/windsurf).

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
