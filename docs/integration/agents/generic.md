---
title: Generic Agent Integration
description: Universal Keylatch integration recipe for any AI agent or coding tool.
---

# Generic Agent Integration

This guide provides a universal recipe for integrating Keylatch with any AI coding tool or agent that is not covered by a specific guide.

## The `CREDENTIALS_LLM_SESSION` signal

`CREDENTIALS_LLM_SESSION` is the generic LLM session signal that any tool can set to activate all Keylatch guards:

```bash
export CREDENTIALS_LLM_SESSION=my-agent-name
```

When this variable is non-empty, Keylatch activates LLM-session mode:

- `keylatch get` — blocked, exit code 2 (SecurityBlock)
- `keylatch run` — allowed for all runtime modes
- `keylatch ui` — scope locked to status-only
- Raw credentials are never returned to the process

## Detection signals

Keylatch checks the following environment variables to detect LLM sessions. The first non-empty value wins:

| Variable | Agent |
|----------|-------|
| `CLAUDE_CODE` | Claude Code |
| `CODEX_ENV` | OpenAI Codex |
| `CURSOR_SESSION` | Cursor |
| `AIDER_SESSION` | Aider |
| `GEMINI_SESSION` | Gemini CLI |
| `OPENCODE_SESSION` | OpenCode |
| `CREDENTIALS_LLM_SESSION` | Any agent (generic fallback) |

## Fallback heuristics

If your agent does not set any of the above signals, you can detect and declare a session using environment inspection:

```bash
#!/usr/bin/env bash
# detect_agent_session.sh — heuristic agent detection
# Source this in your shell rc or project launch script.

# Known agent markers (files or env vars)
detect_agent() {
  # Check env vars first
  for var in CLAUDE_CODE CODEX_ENV CURSOR_SESSION AIDER_SESSION GEMINI_SESSION OPENCODE_SESSION; do
    if [[ -n "${!var:-}" ]]; then
      echo "${var}"
      return 0
    fi
  done

  # Check project-level agent config files
  local markers=(
    ".claude/settings.json"
    ".cursor/settings.json"
    ".windsurf/hooks"
    "AGENTS.md"
    "CLAUDE.md"
    ".gemini/settings.json"
  )

  for marker in "${markers[@]}"; do
    if [[ -e "${marker}" ]]; then
      echo "file:${marker}"
      return 0
    fi
  done

  return 1
}

DETECTED_AGENT=$(detect_agent 2>/dev/null || true)

if [[ -n "${DETECTED_AGENT}" ]]; then
  # Activate Keylatch guards for the detected agent
  export CREDENTIALS_LLM_SESSION="${DETECTED_AGENT}"
  echo "Keylatch: LLM session detected (${DETECTED_AGENT})" >&2
fi
```

## Verifying detection from a script

```bash
# Check detection status
keylatch doctor --category environment --json | python3 -c "
import json, sys
doc = json.load(sys.stdin)
checks = {c['name']: c for c in doc.get('checks', [])}
llm = checks.get('llm.session', {})
print('LLM session detected:', llm.get('warn', False))
print('Detail:', llm.get('detail', 'n/a'))
"
```

## Example detection script

See [docs/integration/examples/agents/detect_session.sh](../examples/agents/detect_session.sh) for a complete example.

## Integrating any tool

For any AI tool:

1. Set `CREDENTIALS_LLM_SESSION=<tool-name>` in the environment where the tool runs.
2. Store credentials with `keylatch connect <provider>`.
3. Wrap tool invocations with `keylatch run`:

```bash
# Generic pattern — works for any tool
keylatch run --clean-env --runtime gateway_typed <provider> -- my-ai-tool
```

4. Optionally install a guard script (if your tool supports pre-command hooks):

```bash
# The guard script exits non-zero on credential exfiltration patterns
~/.keylatch/hooks/block-keylatch-exfiltration.sh
```

## Related

- [docs/integration/README.md](../README.md) — integration guide index
- [docs/integration/agents/claude-code.md](claude-code.md) — Claude Code specifics
- [docs/integration/agents/cursor.md](cursor.md) — Cursor specifics
- [docs/integration/agents/gemini.md](gemini.md) — Gemini CLI specifics
- [docs/integration/agents/windsurf.md](windsurf.md) — Windsurf specifics
