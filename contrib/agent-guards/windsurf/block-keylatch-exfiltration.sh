#!/usr/bin/env bash
# keylatch-hook-version: 3
# Windsurf agent guard — blocks credential-access patterns.
# Note: Windsurf does not currently expose a hook API for tool interception.
# This script is provided for manual invocation or future hook API integration.
# For now, use gateway mode for strongest protection:
#   keylatch proxy start --port 8080
#
# v3 note: adds the `keylatch run -- env` pattern, extends the cat-of-files
# pattern to `.env`, and adds the bare env/printenv structural analyzer that
# the claude-code guard already carries (v3/v4 there) -- these three checks
# were missing entirely from this variant, not merely quote-boundary-weak,
# so `keylatch run -- env`, `cat some.env`, and any form of a bare `env` /
# `printenv` dump (quoted, wrapped in `bash -c '...'`, or plain) previously
# went undetected regardless of quoting. See the claude-code guard's inline
# comments for the full tokenizer rationale and the accepted permanent gaps
# (command substitution, named-variable indirection, file-based payloads,
# unbalanced quotes).
set -euo pipefail

TOOL_NAME="${WINDSURF_TOOL_NAME:-}"
TOOL_INPUT="${WINDSURF_TOOL_INPUT:-}"

block() {
	echo "[hook/keylatch] Blocked: $1" >&2
	exit 2
}

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
				if (nxt == "\n") { i += 2; continue }
				if (nxt == DQ || nxt == "\\" || nxt == "$" || nxt == "`") { cur = cur nxt; i += 2; continue }
				cur = cur c; i++; continue
			}
			if (c == "$" || c == "`") { if (flg != "A") flg = "D" }
			cur = cur c; i++; continue
		}
		if (c == "\\") {
			nxt = substr(s, i+1, 1)
			if (nxt == "\n") { i += 2; continue }
			cur = cur nxt; open = 1; i += 2; continue
		}
		if (c == SQ)   { st = "sq"; open = 1; i++; continue }
		if (c == DQ)   { st = "dq"; open = 1; i++; continue }
		if (c == "$" || c == "`") {
			if (c == "$" && substr(s, i+1, 1) == SQ) { flg = "A" }
			else if (flg != "A") { flg = "D" }
			cur = cur c; open = 1; i++; continue
		}
		if (c == " " || c == "\t") {
			if (open) { cnt++; out_type[cnt]="WORD"; out_val[cnt]=cur; out_flag[cnt]=flg; cur=""; flg=""; open=0 }
			i++; continue
		}
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
function brace_literal(w,    inner, n, alts, i, first) {
	if (w !~ /^\{[^{}]*\}$/) return w
	inner = substr(w, 2, length(w) - 2)
	n = split(inner, alts, ",")
	if (n < 2) return w
	first = ""
	for (i = 1; i <= n; i++) {
		if (alts[i] != "") { first = alts[i]; break }
	}
	if (first == "env" || first == "printenv") return first
	return w
}
function positional_default_literal(w,    p) {
	if (w !~ /^\$\{[1-9](:-|-)[A-Za-z_][A-Za-z0-9_]*\}$/) return w
	p = index(w, "-")
	return substr(w, p + 1, length(w) - p - 1)
}
function resolve_segment(tt, tv, tf, start, end, depth,    i, cw, base, k, j, p, payload) {
	i = start
	while (i <= end && tt[i] == "WORD" && is_in(RESERVED, tv[i])) i++
	while (i <= end && tt[i] == "WORD" && tv[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) i++
	if (i > end) return 0
	cw = tv[i]
	base = brace_literal(cw)
	base = positional_default_literal(base)
	if (index(base, "/") > 0) {
		k = base
		while (index(k, "/") > 0) { k = substr(k, index(k, "/") + 1) }
		base = k
	}
	if (tf[i] == "A") return 1
	if (depth > 0 && tf[i] == "D") return 1
	if (base == "env" || base == "printenv") return 1
	if (is_in(SHELLS, base)) {
		for (j = i + 1; j <= end; j++) {
			if (tt[j] == "WORD" && tv[j] ~ /^-[A-Za-z]*c[A-Za-z]*$/) {
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
Bash|bash|shell|run_command)
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

	# Block keylatch run -- env (env dump via run)
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])keylatch[[:space:]]+run[[:space:]].*--[[:space:]]+env([[:space:]]|$|'|\")"; then
		block "keylatch run -- env is disabled in LLM sessions"
	fi

	# Block cat of keylatch config or keychain-db, or of .env files
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])cat[[:space:]]+.*\.keylatch/(config\.yaml|keylatch\.keychain-db)" || \
	   echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])cat[[:space:]]+.*\.env"; then
		block "cat of keylatch/env files is disabled in LLM sessions"
	fi

	# Block bare env / printenv dump (would expose KEYLATCH_* tokens). Structural
	# tokenizer, not a regex: a plain whitespace/quote boundary cannot tell
	# `bash -c 'env'` (must block) from `grep -n 'env' file` (must allow) --
	# only real shell-word tokenization can. See the claude-code guard's
	# pattern-9 comments for the full design and the accepted permanent gaps
	# (command substitution, named-variable indirection, file-based payloads,
	# unbalanced quotes).
	if printf '%s' "$TOOL_INPUT" | awk "$P9_AWK" | grep -q '^BLOCK$'; then
		block "env/printenv is disabled in LLM sessions to prevent token exfiltration"
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
