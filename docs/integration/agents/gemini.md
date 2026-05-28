---
title: Gemini CLI Integration
description: Using Keylatch with the Gemini CLI agent — detection, BeforeTool hook, GOOGLE credentials.
---

# Gemini CLI Integration

Keylatch integrates with the Gemini CLI at two levels:

1. **Auto-detection** — Keylatch detects active Gemini CLI sessions via the `GEMINI_SESSION` environment variable.
2. **BeforeTool hook** — `keylatch install-guard gemini` writes a `BeforeTool` hook to `~/.gemini/settings.json`.

## Quick start

```bash
# Install the Gemini exfiltration guard
keylatch install-guard gemini

# Verify
keylatch doctor
```

## Detection: `GEMINI_SESSION`

When Gemini CLI is active, it sets the `GEMINI_SESSION` environment variable. Keylatch reads this and activates LLM-session mode automatically. In this mode:

- `keylatch get` — blocked, exit code 2 (SecurityBlock)
- `keylatch run` — allowed for all runtime modes
- Raw credentials are never returned to the Gemini CLI process

If your Gemini environment does not set `GEMINI_SESSION` automatically, you can set the generic fallback:

```bash
export CREDENTIALS_LLM_SESSION=gemini
```

## Storing Gemini / Google AI Studio credentials

Store your Google AI Studio API key with Keylatch:

```bash
# Connect the Google AI Studio provider (creates a 'google-ai' connection)
keylatch connect google-ai
# Or if using the openrouter provider with Google models:
keylatch connect openrouter
```

## Running Gemini CLI with Keylatch

Use `keylatch run` to wrap Gemini CLI invocations in scripts that need additional API calls:

```bash
# Inject credentials into the subprocess environment
keylatch run --clean-env --runtime gateway_typed openrouter -- gemini-cli --model gemini-pro

# Run a script that calls Google AI Studio inside keylatch run
keylatch run --clean-env openrouter -- bash my-gemini-script.sh
```

## BeforeTool hook installation

```bash
keylatch install-guard gemini
# Hook written to: ~/.gemini/settings.json
```

The hook runs a guard script before every Gemini tool call. It blocks patterns like:

- `keylatch get` — direct credential retrieval
- `security find-generic-password` — macOS Keychain access
- `op read` / `bw get` — password manager CLI access
- `cat .env` or reads of `~/.keylatch/` — config file access

## Verifying detection

```bash
# Check that Keylatch can detect your Gemini session:
GEMINI_SESSION=test keylatch doctor --category environment
# Should show: [warn] llm.session: llm_session=true reasons=[GEMINI_SESSION]
```

## Related

- [docs/integrations/gemini.md](../../integrations/gemini.md) — full Gemini guard guide
- [docs/integration/agents/generic.md](generic.md) — universal detection recipe
- [docs/integration/README.md](../README.md) — integration guide index
