#!/usr/bin/env bash
# keylatch-hook-version: 5
# Layer 2 agent guard: blocks credential-access patterns before an agent's
# shell or file-read tool call executes. One script serves every supported
# harness; `--harness <id>` selects the stdin payload shape and the deny
# contract. Layer 1 (CLI-internal GuardLLMSession) still applies when this
# hook is not installed.
#
# Deny contract: exit 2 (exit 1 fails open in most harnesses) with the reason
# on stderr, plus the harness's deny JSON on stdout where one is documented.
# Antigravity documents decisions as stdout JSON only, so it denies with
# exit 0 plus the JSON; a crash or other non-zero exit is reported to block too.
#
#   claude-code, codex  hookSpecificOutput.permissionDecision = deny
#   copilot             permissionDecision = deny
#   gemini              decision = deny
#   antigravity         decision = deny (exit 0)
#   cursor              permission = deny
#   windsurf            exit 2 only (stderr reaches the agent)
#
# Payloads (JSON on stdin):
#   claude-code, codex  {"tool_name":"Bash","tool_input":{"command":"..."}}
#   gemini              {"tool_name":"run_shell_command","tool_input":{"command":"..."}}
#   cursor              {"command":"..."} (beforeShellExecution) or
#                       {"tool_name":"Shell","tool_input":{"command":"..."}}
#   cursor read         {"file_path":"...","attachments":[{"type":"file","file_path":"..."}]}
#   windsurf            {"tool_info":{"command_line":"..."}}
#   windsurf read       {"tool_info":{"file_path":"..."}} (may be a directory)
#   antigravity         {"toolCall":{"name":"run_command","args":{"CommandLine":"..."}}}
#   antigravity read    {"toolCall":{"name":"view_file","args":{"AbsolutePath":"..."}}}
#   copilot             {"tool_name":"Bash","tool_input":{...}} or
#                       {"toolName":"bash","toolArgs":"{\"command\":\"...\"}"}
# CLAUDE_TOOL_NAME / CLAUDE_TOOL_INPUT are honoured as a legacy fallback for
# older harnesses and the test suite.
set -euo pipefail

HARNESS="claude-code"
if [ "${1:-}" = "--harness" ]; then
	HARNESS="${2:-}"
fi
case "$HARNESS" in
claude-code | codex | gemini | cursor | windsurf | copilot | antigravity) ;;
*)
	echo "[hook/keylatch] unknown harness: ${HARNESS}" >&2
	exit 2
	;;
esac

TOOL_NAME="${CLAUDE_TOOL_NAME:-}"
TOOL_INPUT="${CLAUDE_TOOL_INPUT:-}"
# TOOL_COMMAND: a dedicated command string for the structural analyzer.
# TOOL_INPUT may be the raw JSON blob (no-jq fallback) or a file path -- neither
# is a safe thing to feed to a shell-word tokenizer.
TOOL_COMMAND=""
TOOL_FILES=""

# shellcheck disable=SC2016
JQ_COMMAND='def args: ((.toolArgs // empty) | if type == "string" then (try fromjson catch {}) else . end);
	(.tool_input.command // .tool_input.cmd // .command // .tool_info.command_line // .toolCall.args.CommandLine // args.command // empty)
	| if type == "string" then . else empty end'
# shellcheck disable=SC2016
JQ_FILES='def args: ((.toolArgs // empty) | if type == "string" then (try fromjson catch {}) else . end);
	[.tool_input.file_path?, .tool_input.absolute_path?, .tool_input.path?, .file_path?, .tool_info.file_path?, args.path?, .toolCall.args.AbsolutePath?, (.attachments[]?.file_path?)]
	| .[] | select(type == "string" and . != "")'

if [ -z "$TOOL_NAME" ] && [ ! -t 0 ]; then
	STDIN_JSON="$(cat 2>/dev/null || true)"
	if [ -n "$STDIN_JSON" ]; then
		if command -v jq >/dev/null 2>&1; then
			TOOL_NAME="$(printf '%s' "$STDIN_JSON" | jq -r '.tool_name // .toolName // .toolCall.name // empty' 2>/dev/null || true)"
			TOOL_COMMAND="$(printf '%s' "$STDIN_JSON" | jq -r "$JQ_COMMAND" 2>/dev/null || true)"
			TOOL_FILES="$(printf '%s' "$STDIN_JSON" | jq -r "$JQ_FILES" 2>/dev/null || true)"
			TOOL_INPUT="${TOOL_COMMAND:-$TOOL_FILES}"
			[ -n "$TOOL_INPUT" ] || TOOL_INPUT="$(printf '%s' "$STDIN_JSON" | jq -r '.tool_input // empty | tojson' 2>/dev/null || true)"
		else
			# No jq: extract crudely and match patterns against the raw JSON.
			# May over-block; never under-blocks.
			TOOL_NAME="$(printf '%s' "$STDIN_JSON" | sed -n 's/.*"\(tool_name\|toolName\|name\)"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\2/p' | head -n 1)"
			TOOL_INPUT="$STDIN_JSON"
			# Greedy capture is deliberate: over-capture keeps the "may
			# over-block, never under-block" property of this branch.
			TOOL_COMMAND="$(printf '%s' "$STDIN_JSON" | sed -n 's/.*"\(command\|command_line\|CommandLine\)"[[:space:]]*:[[:space:]]*"\(.*\)".*/\2/p' | sed 's/\\"/"/g; s/\\\\/\\/g')"
			if [ -n "$TOOL_COMMAND" ] && [ -z "$TOOL_NAME" ]; then TOOL_NAME="Bash"; fi
		fi
	fi
fi
# jq.exe on Windows ends lines with CRLF; a trailing CR would keep every
# extracted path from matching.
TOOL_NAME="${TOOL_NAME//$'\r'/}"
TOOL_COMMAND="${TOOL_COMMAND//$'\r'/}"
TOOL_FILES="${TOOL_FILES//$'\r'/}"
TOOL_INPUT="${TOOL_INPUT//$'\r'/}"
[ -n "$TOOL_COMMAND" ] || TOOL_COMMAND="$TOOL_INPUT"

case "$TOOL_NAME" in
Bash | bash | Shell | shell | run_shell_command | run_command) TOOL_KIND="Bash" ;;
Read | read_file | read_many_files | view_file | ReadFile) TOOL_KIND="Read" ;;
"")
	if [ -n "$TOOL_COMMAND" ] && [ -z "$TOOL_FILES" ]; then
		TOOL_KIND="Bash"
	elif [ -n "$TOOL_INPUT" ]; then
		TOOL_KIND="Read"
	else
		TOOL_KIND=""
	fi
	;;
*) TOOL_KIND="" ;;
esac

deny_json() {
	case "$HARNESS" in
	claude-code | codex)
		printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}\n' "$1"
		;;
	copilot)
		printf '{"permissionDecision":"deny","permissionDecisionReason":"%s"}\n' "$1"
		;;
	gemini | antigravity)
		printf '{"decision":"deny","reason":"%s"}\n' "$1"
		;;
	cursor)
		printf '{"permission":"deny","user_message":"%s","agent_message":"%s"}\n' "$1" "$1"
		;;
	esac
}

allow_json() {
	case "$HARNESS" in
	gemini | antigravity) printf '{"decision":"allow"}\n' ;;
	cursor) printf '{"permission":"allow"}\n' ;;
	esac
}

block() {
	echo "[hook/keylatch] Blocked: $1" >&2
	deny_json "[hook/keylatch] Blocked: $1"
	if [ "$HARNESS" = "antigravity" ]; then exit 0; fi
	exit 2
}

# Home-relative credential locations the agent must never read directly. A read
# of one of them, of anything inside, or of a directory that contains one (a
# recursive directory read) is denied, and so is a shell reader (cat, head, cp,
# ...) pointed at one. Tools reading their own config as child processes
# (kubectl, gh, docker) are unaffected. Keep this the only list.
PROTECTED_PATHS=".keylatch .ssh .aws .gnupg .local/share/atuin .kube .config/gcloud .docker/config.json .netrc .config/gh/hosts.yml .git-credentials .npmrc .pypirc .azure .terraform.d/credentials.tfrc.json"

PROTECTED_RE=""
for d in $PROTECTED_PATHS; do
	PROTECTED_RE="${PROTECTED_RE:+$PROTECTED_RE|}${d//./\\.}"
done
HOME_RE="${HOME//./\\.}"
READ_CMDS="cat|less|more|head|tail|bat|nl|tac|strings|xxd|od|base64|cp|mv|grep|egrep|rg|awk|sed|sort|cut|tee|scp|rsync"
SHELL_READ_RE="(^|[[:space:];&|(\"'])($READ_CMDS)[[:space:]]+[^;&|]*(~|\\\$HOME|\\\$\{HOME\}|$HOME_RE)/($PROTECTED_RE)([/[:space:]\"']|\$)"

# Windows harnesses send C:\Users\... paths while Git Bash spells HOME as
# /c/Users/..., and Windows paths are case-insensitive: map both sides to the
# /c/... form and compare them in lower case there.
case "$(uname -s 2>/dev/null)" in
MINGW* | MSYS* | CYGWIN*) FOLD_CASE=1 ;;
*) FOLD_CASE=0 ;;
esac

norm_path() {
	local p="${1//\\//}"
	case "$p" in
	[A-Za-z]:/* | [A-Za-z]:) p="/$(printf '%s' "${p:0:1}" | tr '[:upper:]' '[:lower:]')${p:2}" ;;
	esac
	if [ "$FOLD_CASE" = 1 ]; then
		p="$(printf '%s' "$p" | tr '[:upper:]' '[:lower:]')"
	fi
	printf '%s' "$p"
}

# resolve_path normalizes a path and, where realpath exists, resolves
# symlinks and Windows short names, so both sides of a comparison agree.
resolve_path() {
	local p
	p="$(norm_path "$1")"
	if command -v realpath >/dev/null 2>&1; then
		p="$(norm_path "$(realpath -m -- "$p" 2>/dev/null || printf '%s' "$p")")"
	fi
	printf '%s' "${p%/}"
}

path_denied() {
	local p="$1" d prot home
	# shellcheck disable=SC2088
	case "$p" in
	"~") p="$HOME" ;;
	"~/"*) p="$HOME/${p#"~/"}" ;;
	esac
	p="$(resolve_path "$p")"
	home="$(resolve_path "$HOME")"
	for d in $PROTECTED_PATHS; do
		prot="$home/$d"
		case "$p/" in "$prot"/*) return 0 ;; esac
		case "$prot/" in "$p"/*) return 0 ;; esac
	done
	return 1
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
				# Backslash-newline is a line continuation inside double
				# quotes too (POSIX: \ retains escaping meaning before $,
				# `, ", \, and newline) -- must be stripped here the same
				# way as the unquoted case below, or `"e\<newline>nv"`
				# survives as a literal byte and is never recognized as env.
				if (nxt == "\n") { i += 2; continue }
				if (nxt == DQ || nxt == "\\" || nxt == "$" || nxt == "`") { cur = cur nxt; i += 2; continue }
				cur = cur c; i++; continue
			}
			if (c == "$" || c == "`") { if (flg != "A") flg = "D" }
			cur = cur c; i++; continue
		}
		if (c == "\\") {
			nxt = substr(s, i+1, 1)
			# Unquoted backslash-newline is POSIX line continuation, not an
			# escaped character -- both bytes are removed and emit nothing,
			# so `bash \<newline>-c env` still tokenizes to bash, -c, env
			# instead of corrupting the following -c token.
			if (nxt == "\n") { i += 2; continue }
			cur = cur nxt; open = 1; i += 2; continue
		}
		if (c == SQ)   { st = "sq"; open = 1; i++; continue }
		if (c == DQ)   { st = "dq"; open = 1; i++; continue }
		if (c == "$" || c == "`") {
			# An unquoted $ immediately followed by a single quote is
			# ANSI-C quoting (bash dollar-single-quote syntax) -- a pure
			# deterministic string transform, not "unresolvable without
			# execution" like $(...)/backtick/$VAR. Flagged distinctly (A)
			# so resolve_segment can block it unconditionally, not just
			# inside a -c/eval payload (depth > 0). Dollar-single-quote is
			# NOT recognized as ANSI-C quoting inside double quotes in real
			# bash (verified), so this only applies here in the unquoted
			# branch, not in dq.
			if (c == "$" && substr(s, i+1, 1) == SQ) { flg = "A" }
			else if (flg != "A") { flg = "D" }
			cur = cur c; open = 1; i++; continue
		}
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
# Resolves a bare {a,b,...} brace-list token to the first non-empty
# alternative, when it collapses to a single literal command word exactly
# the way real bash brace expansion + unquoted word splitting does: e.g.
# {env,} -> env (the empty alternative vanishes, no execution needed to
# know that). Requires a real comma (bash does not treat {env} without a
# comma as brace expansion at all -- verified). Deliberately narrow: only
# a bare, non-nested {...} occupying the WHOLE token, no prefix/suffix.
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

# Resolves ${N:-literal} / ${N-literal} for positional parameters 1-9 to
# the literal, since Claude Code Bash tool calls never append extra
# positional args to the command string -- $1-$9 are deterministically
# unset in this guard actual deployment context, making the default
# branch always fire (no execution needed to know that). Deliberately
# excludes named variables (${x:-env} stays a gap -- x could be externally
# set) and $0 (always set to the invoking shell/script name in practice,
# so its default branch never fires -- not a real bypass vector).
function positional_default_literal(w,    p) {
	if (w !~ /^\$\{[1-9](:-|-)[A-Za-z_][A-Za-z0-9_]*\}$/) return w
	p = index(w, "-")
	return substr(w, p + 1, length(w) - p - 1)
}

# env followed by a command only runs that command; env with no command
# prints the environment. Options are accepted only when they can neither
# print the environment nor re-parse a string as a command (-S does), and
# -C/--chdir must name an absolute directory. Anything else is blocked.
function env_segment(tt, tv, tf, j, end, depth,    w) {
	while (j <= end) {
		w = tv[j]
		if (w == "--") { j++; break }
		if (w == "-" || w == "-i" || w == "--ignore-environment") { j++; continue }
		if (w == "-u" || w == "--unset") { if (j + 1 > end) return 1; j += 2; continue }
		if (w ~ /^--unset=[A-Za-z_][A-Za-z0-9_]*$/) { j++; continue }
		if (w == "-C" || w == "--chdir") {
			if (j + 1 > end || tv[j + 1] !~ /^\//) return 1
			j += 2; continue
		}
		if (w ~ /^--chdir=\//) { j++; continue }
		if (w ~ /^-/) return 1
		break
	}
	while (j <= end && tv[j] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) j++
	if (j > end) return 1
	return resolve_segment(tt, tv, tf, j, end, depth)
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
	# ANSI-C-quote-tainted words (A) are blocked at any depth --
	# deterministic decode, not an execution-dependent gap. Command
	# substitution/backtick/variable-expansion taint (D) stays gated to
	# depth > 0 (inside a -c/eval payload); allowed bare at top level.
	if (tf[i] == "A") return 1
	if (depth > 0 && tf[i] == "D") return 1
	if (base == "printenv") return 1
	if (base == "env") return env_segment(tt, tv, tf, i + 1, end, depth)
	if (base == "direnv") {
		j = i + 1
		while (j <= end && tv[j] ~ /^-/) j++
		if (j > end) return 0
		if (tv[j] == "export" || tv[j] == "dump") return 1
		if (tv[j] == "exec" && j + 2 <= end) return resolve_segment(tt, tv, tf, j + 2, end, depth)
		return 0
	}
	if (base == "mise") {
		j = i + 1
		while (j <= end && tv[j] ~ /^-/) j++
		if (j > end) return 0
		if (tv[j] == "env" || tv[j] == "e") return 1
		if (tv[j] == "set" && j == end) return 1
		if (tv[j] == "exec" || tv[j] == "x") {
			for (k = j + 1; k <= end; k++) {
				if (tv[k] == "--") {
					if (k + 1 <= end) return resolve_segment(tt, tv, tf, k + 1, end, depth)
					return 0
				}
			}
		}
		return 0
	}
	if (base == "atuin") {
		j = i + 1
		while (j <= end && tv[j] ~ /^-/) j++
		if (j <= end && (tv[j] == "search" || tv[j] == "history")) return 1
		return 0
	}
	if (is_in(SHELLS, base)) {
		for (j = i + 1; j <= end; j++) {
			if (tt[j] == "WORD" && tv[j] ~ /^-[A-Za-z]*c[A-Za-z]*$/) {
				p = j + 1
				# Skip additional dash-flag tokens between -c and the payload
				# word. Real bash keeps parsing short flags after -c (e.g.
				# `bash -c -x env` genuinely runs env with xtrace on --
				# verified empirically), so the payload is the first
				# NON-flag token after the -c match, not necessarily the
				# immediate next one. Do not "simplify" this back to
				# tv[j+1] -- that reopens the bypass this comment is about.
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

HISTORY_PATHS="(\.local/share/atuin|(^|[/[:space:]'\"])\.[A-Za-z0-9_]*_history([[:space:]'\"]|$))"

case "$TOOL_KIND" in
Bash)
	# pattern 1: keylatch get without --masked
	# Allow quotes around command (SEC3 quoting variants).
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])keylatch[[:space:]]+get([[:space:]]|$|'|\")" && \
	   ! echo "$TOOL_INPUT" | grep -qE '\-\-masked'; then
		block "keylatch get is disabled in LLM sessions; use keylatch get --masked or keylatch run"
	fi

	# pattern 2: macOS security command — generic password
	# Quote-aware boundary (SEC3 quoting variants) — matches pattern 1's shape
	# so `bash -c '...'` / `sh -c "..."` wrappers cannot evade the whitespace
	# boundary by starting the segment right after a quote character.
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])security[[:space:]]+find-generic-password"; then
		block "security find-generic-password is disabled in LLM sessions"
	fi

	# pattern 3: macOS security command — internet password
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])security[[:space:]]+find-internet-password"; then
		block "security find-internet-password is disabled in LLM sessions"
	fi

	# pattern 4: 1Password CLI
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])op[[:space:]]+(read|item[[:space:]]+get)"; then
		block "op read / op item get is disabled in LLM sessions"
	fi

	# pattern 5: Bitwarden CLI
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])bw[[:space:]]+(get|list)"; then
		block "bw get / bw list is disabled in LLM sessions"
	fi

	# pattern 7: keylatch run -- env (env dump via run)
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])keylatch[[:space:]]+run[[:space:]].*--[[:space:]]+env([[:space:]]|$|'|\")"; then
		block "keylatch run -- env is disabled in LLM sessions"
	fi

	# pattern 8: cat with keylatch path or .env file
	if echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])cat[[:space:]]+.*keylatch" || \
	   echo "$TOOL_INPUT" | grep -qE "(^|[[:space:]'\"])cat[[:space:]]+.*\.env"; then
		block "cat of keylatch/env files is disabled in LLM sessions"
	fi

	# pattern 9: bare env / printenv dump (would expose KEYLATCH_* tokens).
	# Structural analyzer, not a regex: it tokenizes TOOL_COMMAND with real
	# POSIX shell word rules (quote removal, operator splitting) and blocks
	# when env/printenv resolves to command-word position in any segment --
	# directly, behind an interpreter -c payload, behind eval/exec/command/a
	# wrapper (sudo, xargs, timeout, ...), or nested up to depth 8.
	#
	# `env [-C /abs/dir] [-i] [-u NAME] [NAME=value ...] cmd ...` is allowed:
	# env only prints the environment when no command follows. The command
	# after env is analyzed like any other command word, so `env -C /x env`
	# and `env FOO=1 bash -c env` stay blocked, as do env with no command,
	# any other env option (-0, -S, -v, ...) and a relative -C directory.
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
	# command word that is a command substitution, backtick, or variable
	# expansion is blocked without attempting to resolve it -- e.g.
	# `bash -c "$(echo env)"` and `bash -c "$CMD"` are both blocked this
	# way. This is refusal-to-analyze, not a claim to have solved
	# substitution generally.
	#
	# ANSI-C quoting ($'...') is handled differently and more strongly:
	# unlike $(...)/backtick/$VAR, decoding $'...' needs no execution --
	# it is a pure deterministic string transform, the same category of
	# operation this tokenizer already does for '...'/"..." quote removal.
	# So a command word tainted by a leading $' is blocked unconditionally,
	# at ANY depth, not just inside a -c/eval payload -- e.g. a bare
	# top-level `$'\x65nv'` (decodes to `env`) is blocked even with no
	# wrapper at all.
	#
	# Two more deterministic, no-execution-needed sub-cases are resolved
	# the same way, at any depth: bare brace-list command words like
	# `{env,}` / `{,env,}` (the empty alternative vanishes on unquoted
	# word splitting, same as real bash), and positional-parameter
	# defaults `${1:-env}` .. `${9:-printenv}` (Claude Code never appends
	# extra positional args to the command string, so $1-$9 are always
	# unset here and the default literal always fires). Named-variable
	# defaults (`${x:-env}`) are NOT resolved this way -- x could be
	# externally set, so that stays a genuine gap; see below.
	#
	# KNOWN ACCEPTED GAPS (permanent, by design):
	#   - Top-level command substitution, e.g. `$(echo env)` as a bare
	#     command word. Resolving it requires execution, which defeats a
	#     pre-execution guard.
	#   - Variable indirection with a NAMED variable, e.g. `X=env; $X` or
	#     `${x:-env}`. Genuinely undecidable: the variable could be set
	#     externally. Also `$EDITOR file` / `$PYTHON -m pip` are ordinary
	#     idioms, so blocking dynamic command words at top level would be
	#     a broad false-positive surface. (Positional-parameter defaults
	#     `${1:-env}` .. `${9:-printenv}` are NOT in this bucket -- those
	#     are decidable and blocked, see above.)
	#   - File-based payloads, e.g. `bash script.sh` where the script
	#     contains env -- same class as `source file`, `. file`, and
	#     `bash < file`. The guard inspects the tool-call text, not the
	#     filesystem.
	#   - Unbalanced quotes are allowed, not blocked: the real shell would
	#     reject the command too, so nothing executes.
	if printf '%s' "$TOOL_COMMAND" | awk "$P9_AWK" | grep -q '^BLOCK$'; then
		block "env/printenv and env/history managers (direnv, mise, atuin) are disabled in LLM sessions to prevent token exfiltration"
	fi

	# pattern 10: shell history files and atuin's database
	if echo "$TOOL_INPUT" | grep -qE "$HISTORY_PATHS"; then
		block "shell history and atuin data are disabled in LLM sessions"
	fi

	# pattern 11: shell readers pointed at credential stores
	if printf '%s' "$TOOL_COMMAND" | grep -qE "$SHELL_READ_RE"; then
		block "direct reads of credential files (kube, cloud, docker, netrc, git, npm, pypi, ssh, gpg) are disabled in LLM sessions"
	fi
	;;

Read)
	# pattern 6: Read tool accessing .keylatch/ paths. Matches both
	# tilde-prefixed and absolute paths (Claude Code sends absolute file_path).
	if echo "$TOOL_INPUT" | grep -qE '(^|/)\.keylatch/'; then
		block "direct Read of ~/.keylatch/ is disabled in LLM sessions"
	fi
	if echo "$TOOL_INPUT" | grep -qE "$HISTORY_PATHS"; then
		block "shell history and atuin data are disabled in LLM sessions"
	fi
	[ -n "$TOOL_FILES" ] || TOOL_FILES="$TOOL_INPUT"
	while IFS= read -r read_path; do
		[ -n "$read_path" ] || continue
		if path_denied "$read_path"; then
			block "reads of Keylatch state, SSH, cloud and GPG credentials are disabled in LLM sessions"
		fi
	done <<KL_PATHS
$TOOL_FILES
KL_PATHS
	;;
esac

allow_json
exit 0
