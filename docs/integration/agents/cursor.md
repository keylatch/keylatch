---
title: Cursor Integration
description: Using Keylatch with Cursor — auto-detection, PreToolUse hook, .cursor/rules patterns.
---

# Cursor Integration

Keylatch integrates with Cursor at two levels:

1. **Auto-detection** — Keylatch detects active Cursor sessions via the `CURSOR_SESSION` environment variable.
2. **PreToolUse hook** — `keylatch install-guard cursor` writes a hook to `~/.cursor/settings.json`.

## Quick start

```bash
# Install the Cursor exfiltration guard
keylatch install-guard cursor

# Verify
keylatch doctor
```

## Detection: `CURSOR_SESSION`

When Cursor is active, it sets the `CURSOR_SESSION` environment variable. Keylatch reads this and activates LLM-session mode automatically. In this mode:

- `keylatch get` — blocked, exit code 2 (SecurityBlock)
- `keylatch run` — allowed for all runtime modes
- Raw credentials are never returned to the Cursor process

If your Cursor environment does not set `CURSOR_SESSION` automatically, use the generic fallback:

```bash
export CREDENTIALS_LLM_SESSION=cursor
```

## `.cursor/rules` — project-level credential rules

You can add a `.cursor/rules` file to your project to instruct Cursor not to attempt direct credential retrieval. This is a best-effort hint to the LLM, not a security boundary (Keylatch Layer 1 and Layer 2 guards are the actual enforcement):

```
# .cursor/rules
# Credentials are managed by Keylatch — do not attempt to read .env files,
# ~/.keylatch/, or use keylatch get directly.
# Use: keylatch run --clean-env <provider> -- <command>
```

## Terminal hook pattern

For the Cursor integrated terminal, add `CREDENTIALS_LLM_SESSION=cursor` to your shell rc so the guard is active in all Cursor terminal sessions:

```bash
# ~/.zshrc or ~/.bashrc
export CREDENTIALS_LLM_SESSION=cursor
```

Then reload: `source ~/.zshrc`

## PreToolUse hook installation

```bash
keylatch install-guard cursor
# Hook written to: ~/.cursor/settings.json
```

The hook blocks credential exfiltration patterns before they execute in Cursor's tool-use pipeline.

## Verifying the guard

```bash
keylatch doctor
# Look for: [ok  ] hook.preToolUse: keylatch preToolUse hook detected
# or the llm.session check showing CURSOR_SESSION
```

## Example: using credentials in Cursor sessions

```bash
# Run a script with Keylatch-managed credentials
keylatch run --clean-env --runtime gateway_typed openrouter -- python3 my_script.py

# Dry-run to confirm what would be injected
keylatch run --dry-run openrouter -- python3 my_script.py
```

## Related

- [docs/integrations/cursor.md](../../integrations/cursor.md) — full Cursor guard guide
- [docs/integration/agents/generic.md](generic.md) — universal detection recipe
- [docs/integration/README.md](../README.md) — integration guide index
