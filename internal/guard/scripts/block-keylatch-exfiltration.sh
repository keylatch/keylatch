#!/usr/bin/env bash
# keylatch-hook-version: 3
# Layer 2 agent guard — blocks credential-access patterns before the agent's
# Bash/Read tool calls execute. Layer 1 (CLI-internal GuardLLMSession) still
# applies even when this hook is not installed.
#
# v3 note: patterns 2, 3, 4, 5, 7, 8 gained a quote-wrap-bypass fix (a
# `bash -c '...'` / `sh -c "..."` wrapper could no longer evade the
# whitespace command-boundary check). Pattern 9 (env/printenv) did NOT
# receive the equivalent round-2/round-3 quote-awareness widening — that
# widening was reverted after a third adversarial review round found new
# regex bypasses in that specific area. See the KNOWN LIMITATION comment
# above pattern 9 below for the accepted, documented gap.
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
	# Quote-aware boundary (SEC3 quoting variants) — matches pattern 1's shape
	# so `bash -c '...'` / `sh -c "..."` wrappers cannot evade the whitespace
	# boundary by starting the segment right after a quote character.
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])security[[:space:]]+find-generic-password"; then
		block "security find-generic-password is disabled in LLM sessions"
	fi

	# S0-6 pattern 3: macOS security command — internet password
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])security[[:space:]]+find-internet-password"; then
		block "security find-internet-password is disabled in LLM sessions"
	fi

	# S0-6 pattern 4: 1Password CLI
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])op[[:space:]]+(read|item[[:space:]]+get)"; then
		block "op read / op item get is disabled in LLM sessions"
	fi

	# S0-6 pattern 5: Bitwarden CLI
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])bw[[:space:]]+(get|list)"; then
		block "bw get / bw list is disabled in LLM sessions"
	fi

	# S0-6 pattern 7: keylatch run -- env (env dump via run)
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])keylatch[[:space:]]+run[[:space:]].*--[[:space:]]+env([[:space:]]|$|'|\")"; then
		block "keylatch run -- env is disabled in LLM sessions"
	fi

	# S0-6 pattern 8: cat with keylatch path or .env file
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])cat[[:space:]]+.*keylatch" || \
	   echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])cat[[:space:]]+.*\.env"; then
		block "cat of keylatch/env files is disabled in LLM sessions"
	fi

	# S0-6 pattern 9: bare env / printenv dump (would expose KEYLATCH_* tokens).
	# Command-position anchor (stronger than a plain whitespace boundary,
	# because "env" is a common substring in prose/JSON and a plain
	# whitespace/quote boundary alone would over-block e.g.
	# `grep -n '"env"' settings.json`). Leading group accepts: start of
	# string (optionally itself a quote, for a fully-quoted bare command),
	# one or more shell separator/subshell chars (;, &, |, "(" — repeated to
	# cover && / ||), or a single whitespace char optionally followed by one
	# quote char (covers `bash -c '...'` / `sh -c "..."` wrapping). A quote
	# only counts as a boundary when it is itself adjacent to a real
	# command-start position — an embedded quote pair inside unrelated text
	# (like the settings.json example above) is not preceded by whitespace
	# immediately before "env" and so does not match. VAR=val prefixes
	# before env/printenv are still tolerated.
	#
	# KNOWN LIMITATION (tracked in a follow-up plan): this pattern does not
	# detect env/printenv invoked via bash -c/sh -c/zsh -c with unquoted,
	# adjacent-quote-spliced, ANSI-C-escaped, or command-substitution-
	# obscured payloads, nor via eval/exec/command. Closing the command-
	# substitution and variable-indirection cases specifically requires
	# runtime execution and is not achievable by any static pre-execution
	# check — accepted as permanent residual risk. The remaining gaps
	# (unquoted -c value, eval/exec/command, nested wrappers) are
	# technically closeable but were reverted here after 3 review rounds
	# each found new regex bypasses in this area; a structural rewrite
	# (deny-by-default: any -c/eval/exec/command payload must reduce via
	# real shell tokenization to a static literal token) is the
	# recommended fix, not further regex patching.
	if echo "$TOOL_INPUT" | grep -qE "(^['\"]?|[;&|(]+|[[:space:]]['\"]?)[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+)*(env|printenv)([[:space:]]|$|[;&|)'\"])"; then
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
