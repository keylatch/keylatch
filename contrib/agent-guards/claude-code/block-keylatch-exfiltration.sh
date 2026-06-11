#!/usr/bin/env bash
# keylatch-hook-version: 2
# Layer 2 agent guard — blocks credential-access patterns before the agent's
# Bash/Read tool calls execute. Layer 1 (CLI-internal GuardLLMSession) still
# applies even when this hook is not installed.
#
# Claude Code delivers the tool call as JSON on stdin:
#   {"tool_name": "Bash", "tool_input": {"command": "..."}}
# The CLAUDE_TOOL_NAME / CLAUDE_TOOL_INPUT environment variables are honoured
# as a legacy fallback for older harnesses and the test suite.
set -euo pipefail

TOOL_NAME="${CLAUDE_TOOL_NAME:-}"
TOOL_INPUT="${CLAUDE_TOOL_INPUT:-}"

if [ -z "$TOOL_NAME" ] && [ ! -t 0 ]; then
	STDIN_JSON="$(cat 2>/dev/null || true)"
	if [ -n "$STDIN_JSON" ]; then
		if command -v jq >/dev/null 2>&1; then
			TOOL_NAME="$(printf '%s' "$STDIN_JSON" | jq -r '.tool_name // empty' 2>/dev/null || true)"
			TOOL_INPUT="$(printf '%s' "$STDIN_JSON" | jq -r '.tool_input | if type == "object" then (.command // .file_path // tojson) else tostring end' 2>/dev/null || true)"
		else
			# No jq: extract tool_name crudely and match patterns against the
			# raw JSON. May over-block; never under-blocks.
			TOOL_NAME="$(printf '%s' "$STDIN_JSON" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
			TOOL_INPUT="$STDIN_JSON"
		fi
	fi
fi

block() {
	echo "[hook/keylatch] Blocked: $1" >&2
	exit 2
}

case "$TOOL_NAME" in
Bash)
	# S0-6 pattern 1: keylatch get without --masked
	# Allow quotes around command (SEC3 quoting variants).
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])keylatch[[:space:]]+get([[:space:]]|$|'|\")" && \
	   ! echo "$TOOL_INPUT" | grep -qE '\-\-masked'; then
		block "keylatch get is disabled in LLM sessions; use keylatch get --masked or keylatch run"
	fi

	# S0-6 pattern 2: macOS security command — generic password
	if echo "$TOOL_INPUT" | grep -qE '(^|[[:space:]])security[[:space:]]+find-generic-password'; then
		block "security find-generic-password is disabled in LLM sessions"
	fi

	# S0-6 pattern 3: macOS security command — internet password
	if echo "$TOOL_INPUT" | grep -qE '(^|[[:space:]])security[[:space:]]+find-internet-password'; then
		block "security find-internet-password is disabled in LLM sessions"
	fi

	# S0-6 pattern 4: 1Password CLI
	if echo "$TOOL_INPUT" | grep -qE '(^|[[:space:]])op[[:space:]]+(read|item[[:space:]]+get)'; then
		block "op read / op item get is disabled in LLM sessions"
	fi

	# S0-6 pattern 5: Bitwarden CLI
	if echo "$TOOL_INPUT" | grep -qE '(^|[[:space:]])bw[[:space:]]+(get|list)'; then
		block "bw get / bw list is disabled in LLM sessions"
	fi

	# S0-6 pattern 7: keylatch run -- env (env dump via run)
	if echo "$TOOL_INPUT" | grep -qE '(^|[[:space:]])keylatch[[:space:]]+run[[:space:]].*--[[:space:]]+env([[:space:]]|$)'; then
		block "keylatch run -- env is disabled in LLM sessions"
	fi

	# S0-6 pattern 8: cat with keylatch path or .env file
	if echo "$TOOL_INPUT" | grep -qE '(^|[[:space:]])cat[[:space:]]+.*keylatch' || \
	   echo "$TOOL_INPUT" | grep -qE '(^|[[:space:]])cat[[:space:]]+.*\.env'; then
		block "cat of keylatch/env files is disabled in LLM sessions"
	fi

	# S0-6 pattern 9: bare env / printenv dump (would expose KEYLATCH_* tokens)
	if echo "$TOOL_INPUT" | grep -qE '(^|[[:space:]])(env|printenv)([[:space:]]|$)'; then
		block "env/printenv is disabled in LLM sessions to prevent token exfiltration"
	fi
	;;

Read)
	# S0-6 pattern 6: Read tool accessing .keylatch/ paths. Matches both
	# tilde-prefixed and absolute paths (Claude Code sends absolute file_path).
	if echo "$TOOL_INPUT" | grep -qE '(^|/)\.keylatch/'; then
		block "direct Read of ~/.keylatch/ is disabled in LLM sessions"
	fi
	;;
esac

exit 0
