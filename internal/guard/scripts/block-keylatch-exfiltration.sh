#!/usr/bin/env bash
# keylatch-hook-version: 4
# Layer 2 agent guard — blocks credential-access patterns before the agent's
# Bash/Read tool calls execute. Layer 1 (CLI-internal GuardLLMSession) still
# applies even when this hook is not installed.
#
# v4 note: patterns 2, 3, 4, 5, 7, 8 retain their v3 quote-awareness (a
# `bash -c '...'` / `sh -c "..."` wrapper cannot evade the whitespace
# command-boundary check). Pattern 9 (env/printenv) is replaced by a
# structural tokenizing analyzer (awk, see P9_AWK below) instead of a regex
# -- see the comment above pattern 9 for the design and the accepted gaps.
#
# Claude Code delivers the tool call as JSON on stdin:
#   {"tool_name": "Bash", "tool_input": {"command": "..."}}
# The CLAUDE_TOOL_NAME / CLAUDE_TOOL_INPUT environment variables are honoured
# as a legacy fallback for older harnesses and the test suite.
set -euo pipefail

TOOL_NAME="${CLAUDE_TOOL_NAME:-}"
TOOL_INPUT="${CLAUDE_TOOL_INPUT:-}"
# TOOL_COMMAND: a dedicated command string for pattern 9's structural
# analyzer. TOOL_INPUT above may be the raw JSON blob (no-jq fallback) or a
# file_path (Read tool) -- neither is a safe thing to feed to a shell-word
# tokenizer. TOOL_COMMAND is always either the real command string or empty.
TOOL_COMMAND=""

if [ -z "$TOOL_NAME" ] && [ ! -t 0 ]; then
	STDIN_JSON="$(cat 2>/dev/null || true)"
	if [ -n "$STDIN_JSON" ]; then
		if command -v jq >/dev/null 2>&1; then
			TOOL_NAME="$(printf '%s' "$STDIN_JSON" | jq -r '.tool_name // empty' 2>/dev/null || true)"
			TOOL_INPUT="$(printf '%s' "$STDIN_JSON" | jq -r '.tool_input | if type == "object" then (.command // .file_path // tojson) else tostring end' 2>/dev/null || true)"
			TOOL_COMMAND="$(printf '%s' "$STDIN_JSON" | jq -r '.tool_input.command // empty' 2>/dev/null || true)"
		else
			# No jq: extract tool_name crudely and match patterns against the
			# raw JSON. May over-block; never under-blocks.
			TOOL_NAME="$(printf '%s' "$STDIN_JSON" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
			TOOL_INPUT="$STDIN_JSON"
			# Greedy capture is deliberate: over-capture keeps the "may
			# over-block, never under-block" property of this branch.
			TOOL_COMMAND="$(printf '%s' "$STDIN_JSON" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\(.*\)".*/\1/p' | sed 's/\\"/"/g; s/\\\\/\\/g')"
		fi
	fi
fi
[ -n "$TOOL_COMMAND" ] || TOOL_COMMAND="$TOOL_INPUT"

block() {
	echo "[hook/keylatch] Blocked: $1" >&2
	exit 2
}

# P9_AWK: structural analyzer for pattern 9 (see the comment above pattern 9
# below for the full design rationale). Written as a single-quoted variable
# so the program text is passed to awk verbatim; quote CHARACTERS the
# tokenizer needs to compare against are derived at runtime via sprintf
# (SQ/DQ) rather than embedded literally, since a literal single-quote in
# this string would terminate the bash quoting early. POSIX awk only (no
# gawk extensions) -- must run on both BWK awk (macOS default) and gawk.
# shellcheck disable=SC2016
P9_AWK='
function is_in(list, word) {
	if (word == "") return 0
	return (index(list, " " word " ") > 0)
}
function tokenize(s, out_type, out_val, out_flag,    i, n, c, st, cur, flg, cnt, nxt) {
	n = length(s); i = 1; cnt = 0; cur = ""; flg = ""; st = "none"; open = 0
	while (i <= n) {
		c = substr(s, i, 1)
		if (st == "sq") {
			if (c == SQ) { st = "none" } else { cur = cur c }
			i++; continue
		}
		if (st == "dq") {
			if (c == DQ) { st = "none"; i++; continue }
			if (c == "\\") {
				nxt = substr(s, i+1, 1)
				if (nxt == DQ || nxt == "\\" || nxt == "$" || nxt == "`") { cur = cur nxt; i += 2; continue }
				cur = cur c; i++; continue
			}
			if (c == "$" || c == "`") { flg = "D" }
			cur = cur c; i++; continue
		}
		if (c == "\\") { cur = cur substr(s, i+1, 1); open = 1; i += 2; continue }
		if (c == SQ)   { st = "sq"; open = 1; i++; continue }
		if (c == DQ)   { st = "dq"; open = 1; i++; continue }
		if (c == "$" || c == "`") { flg = "D"; cur = cur c; open = 1; i++; continue }
		if (c == " " || c == "\t") {
			if (open) { cnt++; out_type[cnt]="WORD"; out_val[cnt]=cur; out_flag[cnt]=flg; cur=""; flg=""; open=0 }
			i++; continue
		}
		# An unquoted newline is a real shell command terminator (like a
		# semicolon), not mere word-separating whitespace -- handled as an
		# operator below, not grouped with space/tab above.
		if (c == ";" || c == "&" || c == "|" || c == "(" || c == ")" || c == "\n") {
			if (open) { cnt++; out_type[cnt]="WORD"; out_val[cnt]=cur; out_flag[cnt]=flg; cur=""; flg=""; open=0 }
			while (i < n && substr(s, i+1, 1) == c) { i++ }
			cnt++; out_type[cnt]="OP"; out_val[cnt]=c; out_flag[cnt]=""
			i++; continue
		}
		cur = cur c; open = 1; i++
	}
	if (st != "none") { return -1 }
	if (open) { cnt++; out_type[cnt]="WORD"; out_val[cnt]=cur; out_flag[cnt]=flg }
	return cnt
}
function resolve_segment(tt, tv, tf, start, end, depth,    i, cw, base, k, j, p, payload) {
	i = start
	while (i <= end && tt[i] == "WORD" && is_in(RESERVED, tv[i])) i++
	while (i <= end && tt[i] == "WORD" && tv[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) i++
	if (i > end) return 0
	cw = tv[i]
	base = cw
	if (index(base, "/") > 0) {
		k = base
		while (index(k, "/") > 0) { k = substr(k, index(k, "/") + 1) }
		base = k
	}
	if (depth > 0 && tf[i] == "D") return 1
	if (base == "env" || base == "printenv") return 1
	if (is_in(SHELLS, base)) {
		for (j = i + 1; j <= end; j++) {
			if (tt[j] == "WORD" && tv[j] ~ /^-[A-Za-z]*c$/) {
				p = j + 1
				while (p <= end && tv[p] ~ /^-/) p++
				if (p <= end) {
					payload = tv[p]
					if (index(payload, "$(") > 0 || index(payload, "`") > 0 || index(payload, "$" SQ) > 0) return 1
					if (analyze(payload, depth + 1)) return 1
				}
			}
		}
		return 0
	}
	if (base == "busybox") {
		if (i + 1 <= end) return resolve_segment(tt, tv, tf, i + 1, end, depth)
		return 0
	}
	if (base == "eval") {
		payload = ""
		for (j = i + 1; j <= end; j++) { payload = payload (payload == "" ? "" : " ") tv[j] }
		if (payload == "") return 0
		if (index(payload, "$(") > 0 || index(payload, "`") > 0 || index(payload, "$" SQ) > 0) return 1
		return analyze(payload, depth + 1)
	}
	if (is_in(WRAPPERS, base)) {
		if (base == "command" || base == "builtin") {
			for (j = i + 1; j <= end; j++) { if (tv[j] == "-v" || tv[j] == "-V") return 0 }
		}
		j = i + 1
		while (j <= end && (tv[j] ~ /^-/ || tv[j] ~ /^[0-9]+(\.[0-9]+)?[smhd]?$/)) j++
		if (j > end) return 0
		return resolve_segment(tt, tv, tf, j, end, depth)
	}
	return 0
}
function analyze(text, depth,    tt, tv, tf, n, i, seg_start) {
	if (depth > 8) return 1
	n = tokenize(text, tt, tv, tf)
	if (n == -1) return 0
	seg_start = 1
	for (i = 1; i <= n + 1; i++) {
		if (i > n || tt[i] == "OP") {
			if (i > seg_start) {
				if (resolve_segment(tt, tv, tf, seg_start, i - 1, depth)) return 1
			}
			seg_start = i + 1
		}
	}
	return 0
}
BEGIN {
	SQ = sprintf("%c", 39)
	DQ = sprintf("%c", 34)
	RESERVED = " if then else elif while until do done fi esac case in { } ! time "
	SHELLS   = " bash sh zsh dash ksh mksh ash "
	WRAPPERS = " exec command builtin sudo doas nohup setsid stdbuf nice ionice timeout watch xargs "
}
{ buf = buf (NR > 1 ? "\n" : "") $0 }
END {
	if (analyze(buf, 0)) print "BLOCK"
}
'

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
	# Structural analyzer, not a regex: it tokenizes TOOL_COMMAND with real
	# POSIX shell word rules (quote removal, operator splitting) and blocks
	# when env/printenv resolves to command-word position in any segment --
	# directly, behind an interpreter -c payload, behind eval/exec/command/a
	# wrapper (sudo, xargs, timeout, ...), or nested up to depth 8.
	#
	# Why not a regex: command-word position is a property of shell grammar
	# after quote removal, not of the surrounding characters. A single '
	# immediately before "env" is byte-identical in `bash -c 'env'` (must
	# block) and `grep -n 'env' f` (must allow) -- no character-class
	# boundary can separate them, only tokenization can. Three rounds of
	# regex-only patching each produced a new working bypass; see git log
	# on this file for that history.
	#
	# Deny-by-default rule: inside an interpreter -c / eval payload, a
	# command word that is a command substitution, backtick, ANSI-C $'...'
	# string, or variable expansion is blocked without attempting to
	# resolve it -- e.g. `bash -c "$(echo env)"` and `bash -c "$CMD"` are
	# both blocked this way. This is refusal-to-analyze, not a claim to
	# have solved substitution generally.
	#
	# KNOWN ACCEPTED GAPS (permanent, by design):
	#   - Top-level command substitution, e.g. `$(echo env)` as a bare
	#     command word. Resolving it requires execution, which defeats a
	#     pre-execution guard.
	#   - Variable indirection, e.g. `X=env; $X`. Same reason; also,
	#     `$EDITOR file` / `$PYTHON -m pip` are ordinary idioms, so
	#     blocking dynamic command words at top level would be a broad
	#     false-positive surface.
	#   - File-based payloads, e.g. `bash script.sh` where the script
	#     contains env. The guard inspects the tool-call text, not the
	#     filesystem.
	#   - Unbalanced quotes are allowed, not blocked: the real shell would
	#     reject the command too, so nothing executes.
	if printf '%s' "$TOOL_COMMAND" | awk "$P9_AWK" | grep -q '^BLOCK$'; then
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
