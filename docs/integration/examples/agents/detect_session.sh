#!/usr/bin/env bash
# detect_session.sh — Keylatch agent session detection example.
#
# Source this in your shell rc or call it from a project launch script.
# It checks known agent env vars and project-level marker files, then
# sets CREDENTIALS_LLM_SESSION if an agent environment is detected.
#
# Usage:
#   source detect_session.sh
#   # OR add to ~/.zshrc / ~/.bashrc

set -euo pipefail

# ------------------------------------------------------------
# Known agent environment variable signals
# ------------------------------------------------------------
declare -a AGENT_VARS=(
  "CLAUDE_CODE"
  "CODEX_ENV"
  "CURSOR_SESSION"
  "AIDER_SESSION"
  "GEMINI_SESSION"
  "OPENCODE_SESSION"
)

# ------------------------------------------------------------
# Known project-level agent marker files
# ------------------------------------------------------------
declare -a AGENT_MARKERS=(
  ".claude/settings.json"
  ".cursor/settings.json"
  ".windsurf/hooks"
  "AGENTS.md"
  "CLAUDE.md"
  ".gemini/settings.json"
  ".aider.conf.yml"
  ".codex/hooks.json"
)

# ------------------------------------------------------------
# detect_agent() — returns the detected agent name, or exits 1
# ------------------------------------------------------------
detect_agent() {
  # Check environment variables first (most reliable signal)
  for var in "${AGENT_VARS[@]}"; do
    if [[ -n "${!var:-}" ]]; then
      echo "env:${var}"
      return 0
    fi
  done

  # CREDENTIALS_LLM_SESSION is already set — respect it
  if [[ -n "${CREDENTIALS_LLM_SESSION:-}" ]]; then
    echo "env:CREDENTIALS_LLM_SESSION=${CREDENTIALS_LLM_SESSION}"
    return 0
  fi

  # Fall back to project-level file markers
  for marker in "${AGENT_MARKERS[@]}"; do
    if [[ -e "${marker}" ]]; then
      echo "file:${marker}"
      return 0
    fi
  done

  return 1
}

# ------------------------------------------------------------
# Main logic
# ------------------------------------------------------------
DETECTED_AGENT=""
if DETECTED_AGENT=$(detect_agent 2>/dev/null); then
  # Activate Keylatch LLM-session guards
  export CREDENTIALS_LLM_SESSION="${DETECTED_AGENT}"

  # Verify keylatch is installed before printing advice
  if command -v keylatch >/dev/null 2>&1; then
    echo "[keylatch] LLM session detected: ${DETECTED_AGENT}" >&2
    echo "[keylatch] Credential guards are active. Use 'keylatch doctor' to verify." >&2
  else
    echo "[keylatch] LLM session detected (${DETECTED_AGENT}) — keylatch not found in PATH." >&2
    echo "[keylatch] Install: brew install keylatch/tap/keylatch" >&2
  fi
else
  # No agent detected — no action needed
  if [[ "${KEYLATCH_DETECT_DEBUG:-}" == "1" ]]; then
    echo "[keylatch] No agent environment detected." >&2
  fi
fi
