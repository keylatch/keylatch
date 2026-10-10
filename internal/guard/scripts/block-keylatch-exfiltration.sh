#!/usr/bin/env bash
# keylatch-hook-version: 6
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
# Any unexpected failure inside the guard (an unset HOME, a missing tool, a
# command that errors) is converted to the same deny by the EXIT trap, so the
# guard fails closed.
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
#   copilot read        {"toolName":"view","toolArgs":"{\"path\":\"...\"}"}
# CLAUDE_TOOL_NAME / CLAUDE_TOOL_INPUT are honoured as a legacy fallback for
# older harnesses and the test suite.
#
# Without jq the payload is parsed with sed/grep/awk. File paths are extracted
# from the usual keys, and the raw JSON is also scanned for any protected path;
# that branch may over-block but never under-blocks a protected path.
#
# KNOWN ACCEPTED GAPS of the shell-reader and path checks:
#   - Paths built at run time: variables other than HOME, command
#     substitution, string concatenation, and globs that expand to a protected
#     name (`~/.ss?/id_rsa`). The guard reads the tool-call text only.
#   - Relative paths are only caught after a `cd` to the home directory in the
#     same command; a relative read from a working directory that is already
#     inside a protected location is not.
#   - Commands on the safe list (ls, kubectl, gh, docker, stat) may name a
#     protected path, so `docker run -v ~/.ssh:/k ...` is not blocked.
#   - Interpreters that read a protected path through a variable or an
#     expression (`python3 -c 'open(os.environ["HOME"] + "/.ssh/id_rsa")'`).
#   - env dumps via `export -p`, `declare -x`, `set` and `/proc/self/environ`.
set -euo pipefail

HOME="${HOME:-}"
HARNESS="claude-code"
if [ "${1:-}" = "--harness" ]; then
	HARNESS="${2:-}"
fi

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

DECIDED=0

block() {
	DECIDED=1
	echo "[hook/keylatch] Blocked: $1" >&2
	deny_json "[hook/keylatch] Blocked: $1"
	if [ "$HARNESS" = "antigravity" ]; then exit 0; fi
	exit 2
}

# Anything that ends the script without an allow or a deny decision is an
# internal failure; turn it into a deny.
# shellcheck disable=SC2329
on_exit() {
	local rc=$?
	trap - EXIT
	if [ "$DECIDED" = 1 ]; then exit "$rc"; fi
	echo "[hook/keylatch] Blocked: the guard failed unexpectedly (status $rc) and denies by default" >&2
	deny_json "[hook/keylatch] Blocked: the guard failed unexpectedly and denies by default"
	if [ "$HARNESS" = "antigravity" ]; then exit 0; fi
	exit 2
}
trap on_exit EXIT

case "$HARNESS" in
claude-code | codex | gemini | cursor | windsurf | copilot | antigravity) ;;
*)
	DECIDED=1
	echo "[hook/keylatch] unknown harness: ${HARNESS}" >&2
	exit 2
	;;
esac

# Home-relative credential locations the agent must never read directly. A read
# of one of them, of anything inside, or of a directory that contains one (a
# recursive directory read) is denied, and so is any shell command that names
# one (except the safe list below). Tools reading their own config as child
# processes (kubectl, gh, docker) are unaffected. Keep this the only list.
PROTECTED_PATHS=".keylatch .ssh .aws .gnupg .local/share/atuin .kube .config/gcloud .docker/config.json .netrc .config/gh/hosts.yml .git-credentials .npmrc .pypirc .azure .terraform.d/credentials.tfrc.json"
SAFE_PATH_CMDS="ls kubectl gh docker stat"

re_escape() {
	printf '%s' "$1" | sed -E 's/[][\.*^$+?(){}|/]/\\&/g'
}

PROTECTED_RE=""
for d in $PROTECTED_PATHS; do
	PROTECTED_RE="${PROTECTED_RE:+$PROTECTED_RE|}${d//./\\.}"
done

# Windows paths are case-insensitive and so is the default macOS volume; both
# sides of a comparison are folded to lower case there.
case "$(uname -s 2>/dev/null || true)" in
MINGW* | MSYS* | CYGWIN*)
	FOLD_CASE=1
	WINDOWS=1
	;;
Darwin*)
	FOLD_CASE=1
	WINDOWS=0
	;;
*)
	FOLD_CASE=0
	WINDOWS=0
	;;
esac
CI=""
if [ "$FOLD_CASE" = 1 ]; then CI="i"; fi

# matches <ERE> <text>: grep status 0/1 map to true/false, anything else (a
# grep that rejects the expression) aborts into the fail-closed trap.
matches() {
	local rc=0
	printf '%s\n' "$2" | grep -q${CI}E -- "$1" || rc=$?
	if [ "$rc" -gt 1 ]; then exit 70; fi
	[ "$rc" -eq 0 ]
}

REALPATH_M=0
if command -v realpath >/dev/null 2>&1 && realpath -m -- / >/dev/null 2>&1; then REALPATH_M=1; fi

# lexical_path folds `.`, empty segments and `seg/..` without touching the disk.
lexical_path() {
	local p="$1" rest seg out="" lead=""
	case "$p" in /*) lead="/" ;; esac
	rest="$p"
	while [ -n "$rest" ]; do
		case "$rest" in
		*/*)
			seg="${rest%%/*}"
			rest="${rest#*/}"
			;;
		*)
			seg="$rest"
			rest=""
			;;
		esac
		case "$seg" in
		"" | .) ;;
		..)
			case "$out" in
			"") if [ -z "$lead" ]; then out=".."; fi ;;
			.. | */..) out="$out/.." ;;
			*/*) out="${out%/*}" ;;
			*) out="" ;;
			esac
			;;
		*) out="${out:+$out/}$seg" ;;
		esac
	done
	printf '%s' "$lead$out"
}

squeeze_path() {
	local p="$1"
	while :; do
		case "$p" in
		*//*) p="${p//\/\///}" ;;
		*/./*) p="${p//\/.\///}" ;;
		*) break ;;
		esac
	done
	printf '%s' "${p%/.}"
}

# physical_path resolves a path the way the filesystem would, without GNU
# realpath -m (BSD realpath has no -m): the longest existing directory prefix is
# resolved with cd -P, a trailing symlink is followed, and the part that does
# not exist yet is folded lexically.
physical_path() {
	local p="$1" q d rem res t hops=0
	if [ "$REALPATH_M" = 1 ]; then
		realpath -m -- "$p" 2>/dev/null || printf '%s' "$p"
		return 0
	fi
	case "$p" in /*) ;; *) p="$PWD/$p" ;; esac
	while :; do
		q="$(squeeze_path "$p")"
		d="$q"
		rem=""
		while [ -n "$d" ] && [ ! -d "$d" ]; do
			case "$d" in
			*/*)
				rem="${d##*/}${rem:+/$rem}"
				d="${d%/*}"
				;;
			*)
				rem="$d${rem:+/$rem}"
				d=""
				;;
			esac
		done
		[ -n "$d" ] || d="/"
		d="$(cd -P -- "$d" 2>/dev/null && pwd -P)" || d="$(lexical_path "$q")"
		rem="$(lexical_path "$rem")"
		res="${d%/}${rem:+/$rem}"
		if [ -L "$res" ] && [ "$hops" -lt 8 ]; then
			t="$(readlink "$res" 2>/dev/null)" || t=""
			if [ -n "$t" ]; then
				case "$t" in
				/*) p="$t" ;;
				*) p="${res%/*}/$t" ;;
				esac
				hops=$((hops + 1))
				continue
			fi
		fi
		printf '%s' "$res"
		return 0
	done
}

# Windows harnesses send C:\Users\... paths while Git Bash spells HOME as
# /c/Users/..., so both sides are mapped to the /c/... form.
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

# resolve_path brings a path to one comparable form. On Windows, Git Bash
# mounts parts of the disk elsewhere (the temp folder is /tmp), so cygpath
# turns every path back into its Windows form first; elsewhere symlinks and
# `..` are resolved against the filesystem.
resolve_path() {
	local p="$1"
	if [ "$WINDOWS" = 1 ]; then
		if command -v cygpath >/dev/null 2>&1; then
			p="$(cygpath -w -- "$p" 2>/dev/null || printf '%s' "$p")"
		fi
		p="$(lexical_path "$(norm_path "$p")")"
	else
		p="$(physical_path "$p")"
		if [ "$FOLD_CASE" = 1 ]; then p="$(norm_path "$p")"; fi
	fi
	printf '%s' "${p%/}"
}

# home_forms prints every form HOME may take in a harness payload: on Windows
# both its long and its 8.3 short name.
home_forms() {
	[ -n "$HOME" ] || return 0
	resolve_path "$HOME"
	echo
	if [ "$WINDOWS" = 1 ] && command -v cygpath >/dev/null 2>&1; then
		local f
		for f in -l -s; do
			f="$(cygpath -w "$f" -- "$HOME" 2>/dev/null)" || continue
			f="$(norm_path "$f")"
			printf '%s\n' "${f%/}"
		done
	fi
}

HOME_FORMS_SET=0
HOME_FORMS_TEXT=""
load_home_forms() {
	if [ "$HOME_FORMS_SET" = 0 ]; then
		HOME_FORMS_TEXT="$(home_forms)"
		HOME_FORMS_SET=1
	fi
}

path_denied() {
	local p="$1" d prot home
	[ -n "$p" ] || return 1
	# shellcheck disable=SC2088
	case "$p" in
	"~") p="$HOME" ;;
	"~/"*) p="$HOME/${p#"~/"}" ;;
	esac
	[ -n "$p" ] || return 1
	p="$(resolve_path "$p")"
	load_home_forms
	while IFS= read -r home; do
		[ -n "$home" ] || continue
		for d in $PROTECTED_PATHS; do
			prot="$home/$d"
			case "$p/" in "$prot"/*) return 0 ;; esac
			case "$prot/" in "$p"/*) return 0 ;; esac
		done
	done <<EOF_HOMES
$HOME_FORMS_TEXT
EOF_HOMES
	return 1
}

# path_arg_denied checks a tool path argument; a glob is checked through the
# directory that holds its first wildcard, since the expansion can reach any
# protected name there.
path_arg_denied() {
	local p="$1" dir
	if path_denied "$p"; then return 0; fi
	case "$p" in
	*[\*\?\[\{]*)
		dir="${p%%[\*\?\[\{]*}"
		case "$dir" in
		*/*) dir="${dir%/*}" ;;
		*) dir="." ;;
		esac
		[ -n "$dir" ] || dir="/"
		path_denied "$dir" && return 0
		;;
	esac
	return 1
}

# raw_json_denied scans an unparsed payload for any protected path spelled with
# ~, $HOME or an absolute home, whatever key it sits under.
raw_json_denied() {
	local text homes="" home alt
	text="$(printf '%s' "$1" | sed -E 's#\\\\#/#g; s#\\/#/#g; s#([A-Za-z]):/#/\1/#g')"
	load_home_forms
	while IFS= read -r home; do
		[ -n "$home" ] || continue
		homes="$homes|$(re_escape "$home")"
	done <<EOF_RAW_HOMES
$HOME_FORMS_TEXT
EOF_RAW_HOMES
	alt="~|\\\$HOME|\\\$\\{HOME\\}$homes"
	matches "($alt)/+($PROTECTED_RE)([^A-Za-z0-9_.-]|\$)" "$text"
}

# --- payload parsing ---

# json_unescape decodes the JSON string escapes a shell command or path can
# carry, one input line at a time.
json_unescape() {
	awk '{
		out = ""; n = length($0); i = 1
		while (i <= n) {
			c = substr($0, i, 1)
			if (c == "\\" && i < n) {
				i++; c = substr($0, i, 1)
				if (c == "n") c = "\n"
				else if (c == "t") c = "\t"
				else if (c == "r") c = ""
			}
			out = out c; i++
		}
		print out
	}'
}

# json_string_values <keys-ERE>: every string value under a matching key, in the
# payload and in the JSON that a toolArgs string carries.
json_string_values() {
	{
		printf '%s\n%s\n' "$STDIN_JSON" "$STDIN_UNESCAPED" |
			grep -oE "\"($1)\"[[:space:]]*:[[:space:]]*\"([^\"\\\\]|\\\\.)*\"" |
			sed -E 's/^"[^"]*"[[:space:]]*:[[:space:]]*"(.*)"$/\1/' || true
	} | json_unescape
}

json_array_values() {
	{
		printf '%s\n%s\n' "$STDIN_JSON" "$STDIN_UNESCAPED" |
			grep -oE "\"($1)\"[[:space:]]*:[[:space:]]*\[[^]]*\]" |
			grep -oE '"([^"\\]|\\.)*"' |
			sed -E "/^\"($1)\"\$/d; s/^\"(.*)\"\$/\\1/" || true
	} | json_unescape
}

STDIN_JSON=""
STDIN_UNESCAPED=""
TOOL_NAME="${CLAUDE_TOOL_NAME:-}"
TOOL_INPUT="${CLAUDE_TOOL_INPUT:-}"
# TOOL_COMMAND: a dedicated command string for the structural analyzer.
# TOOL_INPUT may be the raw JSON blob (no-jq fallback) or a file path -- neither
# is a safe thing to feed to a shell-word tokenizer.
TOOL_COMMAND=""
TOOL_FILES=""
NO_JQ=0

# shellcheck disable=SC2016
JQ_COMMAND='def args: ((.toolArgs // empty) | if type == "string" then (try fromjson catch {}) else . end);
	(.tool_input.command // .tool_input.cmd // .command // .tool_info.command_line // .toolCall.args.CommandLine // args.command // empty)
	| if type == "string" then . else empty end'
# shellcheck disable=SC2016
JQ_FILES='def args: ((.toolArgs // empty) | if type == "string" then (try fromjson catch {}) else . end);
	[.tool_input.file_path?, .tool_input.absolute_path?, .tool_input.path?, .tool_input.dir_path?, (.tool_input.paths[]?),
	 (.tool_input.pattern? | select(type == "string" and test("/"))), (.tool_input.glob? | select(type == "string" and test("/"))),
	 .file_path?, .tool_info.file_path?, args.path?, (args.paths[]?), (args.pattern? | select(type == "string" and test("/"))),
	 .toolCall.args.AbsolutePath?, (.attachments[]?.file_path?)]
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
			NO_JQ=1
			STDIN_UNESCAPED="$(printf '%s' "$STDIN_JSON" | sed -E 's/\\"/"/g')"
			TOOL_NAME="$({ printf '%s' "$STDIN_JSON" | sed -En 's/.*"(tool_name|toolName)"[[:space:]]*:[[:space:]]*"([^"]*)".*/\2/p' | head -n 1; } || true)"
			if [ -z "$TOOL_NAME" ]; then
				TOOL_NAME="$({ printf '%s' "$STDIN_JSON" | sed -En 's/.*"name"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' | head -n 1; } || true)"
			fi
			TOOL_INPUT="$STDIN_JSON"
			# Every string under a command key is analysed, so an extra
			# occurrence can only add to what is checked.
			TOOL_COMMAND="$(json_string_values 'command|command_line|CommandLine|cmd')"
			TOOL_FILES="$({
				json_string_values 'file_path|AbsolutePath|absolute_path|path|dir_path'
				json_array_values 'paths'
				{ json_string_values 'pattern|glob' | grep '/' || true; }
			})"
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
Bash | bash | Shell | shell | PowerShell | powershell | run_shell_command | run_command) TOOL_KIND="Bash" ;;
Read | read_file | read_many_files | view_file | ReadFile | view | Grep | grep | Glob | glob | grep_search | search_file_content) TOOL_KIND="Read" ;;
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
		if (tv[j] == "set") {
			for (k = j + 1; k <= end; k++) { if (tv[k] !~ /^-/) break }
			if (k > end) return 1
		}
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

# shell_names_protected_path reports whether a shell command text refers to a
# protected credential location. The text is normalised first (quotes and
# backslashes dropped, repeated slashes, `/./` and `seg/..` folded) so spelling
# tricks do not hide the path, then every command segment that names a
# protected path is denied unless its command word is on the safe list. After a
# `cd` to the home directory, relative protected names count too.
shell_names_protected_path() {
	local norm seg w ref_re rel_re cd_re home_cd=0 homes="" alt safe
	norm="$(printf '%s' "$1" | tr -d "\"'\\\\" | sed -E -e 's#/+#/#g' -e ':a' -e 's#/\./#/#g' -e 's#/[^/[:space:].][^/[:space:]]*/\.\./#/#' -e 's#/\.[^/[:space:].][^/[:space:]]*/\.\./#/#' -e 'ta')"
	if [ -n "$HOME" ]; then homes="|$(re_escape "$HOME")"; fi
	alt="~|\\\$HOME|\\\$\\{HOME\\}$homes"
	ref_re="($alt)/+($PROTECTED_RE)([^A-Za-z0-9_.-]|\$)"
	rel_re="(^|[[:space:]=<>])($PROTECTED_RE)([^A-Za-z0-9_.-]|\$)"
	cd_re="^[[:space:]]*(cd|pushd)([[:space:]]+($alt)?/*)?[[:space:]]*\$"
	while IFS= read -r seg; do
		if matches "$cd_re" "$seg"; then
			home_cd=1
			continue
		fi
		if ! matches "$ref_re" "$seg"; then
			if [ "$home_cd" = 0 ] || ! matches "$rel_re" "$seg"; then continue; fi
		fi
		w="${seg#"${seg%%[![:space:]]*}"}"
		while [[ $w =~ ^[A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*[[:space:]]+ ]]; do
			w="${w#"${BASH_REMATCH[0]}"}"
		done
		w="${w%%[[:space:]]*}"
		w="${w##*/}"
		for safe in $SAFE_PATH_CMDS; do
			if [ "$w" = "$safe" ]; then continue 2; fi
		done
		return 0
	done <<EOF_SEGMENTS
$(printf '%s\n' "$norm" | tr ';&|()' '\n')
EOF_SEGMENTS
	return 1
}

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
	# boundary can separate them, only tokenization can. Repeated regex-only
	# patching each produced a new working bypass; see git log on this file
	# for that history.
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
	P9_RESULT="$(printf '%s' "$TOOL_COMMAND" | awk "$P9_AWK")"
	if [ "$P9_RESULT" = "BLOCK" ]; then
		block "env/printenv and env/history managers (direnv, mise, atuin) are disabled in LLM sessions to prevent token exfiltration"
	fi

	# pattern 10: shell history files and atuin's database
	if echo "$TOOL_INPUT" | grep -qE "$HISTORY_PATHS"; then
		block "shell history and atuin data are disabled in LLM sessions"
	fi

	# pattern 11: any shell command naming a credential store
	if shell_names_protected_path "$TOOL_COMMAND"; then
		block "direct reads of credential files (kube, cloud, docker, netrc, git, npm, pypi, ssh, gpg) are disabled in LLM sessions"
	fi
	;;

Read)
	# pattern 6: Read tool accessing .keylatch/ paths. Matches both
	# tilde-prefixed and absolute paths (Claude Code sends absolute file_path).
	READ_TEXT="$TOOL_INPUT
$TOOL_FILES
$STDIN_UNESCAPED"
	if echo "$READ_TEXT" | grep -qE '(^|/)\.keylatch/'; then
		block "direct Read of ~/.keylatch/ is disabled in LLM sessions"
	fi
	if echo "$READ_TEXT" | grep -qE "$HISTORY_PATHS"; then
		block "shell history and atuin data are disabled in LLM sessions"
	fi
	if [ "$NO_JQ" = 1 ] && raw_json_denied "$STDIN_JSON"; then
		block "reads of Keylatch state, SSH, cloud and GPG credentials are disabled in LLM sessions"
	fi
	[ -n "$TOOL_FILES" ] || TOOL_FILES="$TOOL_INPUT"
	while IFS= read -r read_path; do
		[ -n "$read_path" ] || continue
		if path_arg_denied "$read_path"; then
			block "reads of Keylatch state, SSH, cloud and GPG credentials are disabled in LLM sessions"
		fi
	done <<KL_PATHS
$TOOL_FILES
KL_PATHS
	;;
esac

DECIDED=1
allow_json
exit 0
