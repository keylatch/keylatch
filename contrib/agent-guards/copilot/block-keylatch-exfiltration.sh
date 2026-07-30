#!/usr/bin/env bash
# keylatch-hook-version: 2
# GitHub Copilot CLI guard — blocks credential-access patterns.
# Since the exact native hook config path is unconfirmed (the original gh copilot
# extension is retired), this script is used as a shell wrapper fallback that
# intercepts copilot invocations.
set -euo pipefail

TOOL_NAME="${COPILOT_TOOL_NAME:-}"
TOOL_INPUT="${COPILOT_TOOL_INPUT:-}"

block() {
	echo "[hook/keylatch] Blocked: $1" >&2
	exit 2
}

case "$TOOL_NAME" in
Bash|bash|shell|run_command|execute)
	# Block keylatch get without --masked
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])keylatch[[:space:]]+get([[:space:]]|$|'|\")" && \
	   ! echo "$TOOL_INPUT" | grep -qE '\-\-masked'; then
		block "keylatch get is disabled in LLM sessions; use keylatch get --masked or keylatch run"
	fi

	# Block macOS security commands (quote-aware boundary, SEC3-style)
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])security[[:space:]]+find-(generic|internet)-password"; then
		block "security find-password is disabled in LLM sessions"
	fi

	# Block 1Password CLI
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])op[[:space:]]+(read|item[[:space:]]+get)"; then
		block "op read is disabled in LLM sessions"
	fi

	# Block Bitwarden CLI
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])bw[[:space:]]+(get|list)"; then
		block "bw get is disabled in LLM sessions"
	fi

	# Block cat of keylatch config or keychain-db
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])cat[[:space:]]+.*\.keylatch/(config\.yaml|keylatch\.keychain-db)"; then
		block "cat of .keylatch files is disabled in LLM sessions"
	fi
	;;

read_file|ReadFile)
	# Block direct reads of ~/.keylatch/ paths
	if echo "$TOOL_INPUT" | grep -qE '(^|~/)\.keylatch/'; then
		block "direct read of ~/.keylatch/ is disabled in LLM sessions"
	fi
	;;
esac

exit 0
