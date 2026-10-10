#!/usr/bin/env bash
# shellcheck disable=SC2034
# Shared helpers for the guard tests: builds the stdin payload each harness
# sends to its pre-tool hook and runs the guard the way the harness does.

GUARD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$GUARD_DIR/claude-code/block-keylatch-exfiltration.sh"

HARNESSES="claude-code codex gemini cursor windsurf copilot antigravity"

# shell_payload <harness> <command>
shell_payload() {
	case "$1" in
	claude-code | codex) jq -nc --arg c "$2" '{hook_event_name:"PreToolUse",tool_name:"Bash",tool_input:{command:$c}}' ;;
	gemini) jq -nc --arg c "$2" '{hook_event_name:"BeforeTool",tool_name:"run_shell_command",tool_input:{command:$c}}' ;;
	cursor) jq -nc --arg c "$2" '{hook_event_name:"beforeShellExecution",command:$c,cwd:"/work",sandbox:false}' ;;
	windsurf) jq -nc --arg c "$2" '{agent_action_name:"pre_run_command",tool_info:{command_line:$c,cwd:"/work"}}' ;;
	antigravity) jq -nc --arg c "$2" '{toolCall:{name:"run_command",args:{CommandLine:$c}},stepIdx:1}' ;;
	copilot) jq -nc --arg c "$2" '{hook_event_name:"PreToolUse",tool_name:"Bash",tool_input:{command:$c}}' ;;
	esac
}

# copilot_camel_payload <command>: the camelCase event shape, where toolArgs is a JSON string.
copilot_camel_payload() {
	jq -nc --arg c "$1" '{toolName:"bash",toolArgs:({command:$c}|tojson)}'
}

# copilot_view_payload <path>: Copilot CLI's file-read tool is `view`; its
# camelCase hook event carries the arguments as a JSON string.
copilot_view_payload() {
	jq -nc --arg p "$1" '{toolName:"view",toolArgs:({path:$p}|tojson)}'
}

# read_payload <harness> <path>: the harness's file-read hook payload.
read_payload() {
	case "$1" in
	claude-code | codex) jq -nc --arg p "$2" '{tool_name:"Read",tool_input:{file_path:$p}}' ;;
	copilot) copilot_view_payload "$2" ;;
	gemini) jq -nc --arg p "$2" '{tool_name:"read_file",tool_input:{file_path:$p}}' ;;
	cursor) jq -nc --arg p "$2" '{hook_event_name:"beforeReadFile",file_path:$p,content:"",attachments:[]}' ;;
	windsurf) jq -nc --arg p "$2" '{agent_action_name:"pre_read_code",tool_info:{file_path:$p}}' ;;
	antigravity) jq -nc --arg p "$2" '{toolCall:{name:"view_file",args:{AbsolutePath:$p}},stepIdx:2}' ;;
	esac
}

# cursor_attachment_payload <file> <attached path>
cursor_attachment_payload() {
	jq -nc --arg f "$1" --arg a "$2" '{hook_event_name:"beforeReadFile",file_path:$f,content:"",attachments:[{type:"file",file_path:$a}]}'
}

# deny_code <harness>: the exit status a deny produces. Antigravity reads
# decisions from stdout JSON only.
deny_code() {
	if [ "$1" = antigravity ]; then echo 0; else echo 2; fi
}

# make_tool_dir <dir> [nojq]: a PATH directory holding the tools the guard
# needs. With "nojq" it leaves jq out and puts a BSD-like sed in front, one that
# rejects the GNU-only \| alternation, so the no-jq branch is exercised the way
# it runs on a stock macOS.
make_tool_dir() {
	local dir="$1" mode="${2:-}" t src
	mkdir -p "$dir"
	for t in bash sh awk grep head cat tr uname realpath readlink dirname basename mktemp rm env cut sort ln mkdir date; do
		src="$(command -v "$t" 2>/dev/null)" || continue
		ln -sf "$src" "$dir/$t"
	done
	if [ "$mode" = nojq ]; then
		rm -f "$dir/sed"
		cat >"$dir/sed" <<SEDEOF
#!/bin/sh
for a in "\$@"; do
	case "\$a" in
	*'\|'*) echo "sed: unsupported GNU alternation" >&2; exit 1 ;;
	esac
done
exec $(command -v sed) "\$@"
SEDEOF
		chmod +x "$dir/sed"
	else
		ln -sf "$(command -v sed)" "$dir/sed"
		ln -sf "$(command -v jq)" "$dir/jq"
	fi
}

GUARD_PATH_DIR=""
if [ "${KEYLATCH_TEST_NO_JQ:-}" = 1 ]; then
	GUARD_PATH_DIR="$(mktemp -d)"
	make_tool_dir "$GUARD_PATH_DIR" nojq
fi

# run_guard <harness> <payload>: sets GUARD_CODE, GUARD_OUT, GUARD_ERR. With
# KEYLATCH_TEST_NO_JQ=1 the guard runs without jq on a BSD-like sed.
run_guard() {
	local errfile guard_path="${GUARD_PATH_DIR:-$PATH}"
	errfile="$(mktemp)"
	GUARD_CODE=0
	# shellcheck disable=SC2086
	GUARD_OUT="$(printf '%s' "$2" | env -u CLAUDE_TOOL_NAME -u CLAUDE_TOOL_INPUT ${GUARD_ENV_OPTS:-} PATH="${GUARD_STUB_DIR:+$GUARD_STUB_DIR:}$guard_path" "$BASH" "$HOOK" --harness "$1" 2>"$errfile")" || GUARD_CODE=$?
	GUARD_ERR="$(<"$errfile")"
	rm -f "$errfile"
}

# deny_json_ok <harness> <stdout>: the documented deny JSON, or empty output
# for a harness that only reads the exit code.
deny_json_ok() {
	case "$1" in
	claude-code | codex) printf '%s' "$2" | jq -e '.hookSpecificOutput.hookEventName == "PreToolUse" and .hookSpecificOutput.permissionDecision == "deny" and (.hookSpecificOutput.permissionDecisionReason | length > 0)' >/dev/null 2>&1 ;;
	copilot) printf '%s' "$2" | jq -e '.permissionDecision == "deny" and (.permissionDecisionReason | length > 0)' >/dev/null 2>&1 ;;
	gemini | antigravity) printf '%s' "$2" | jq -e '.decision == "deny" and (.reason | length > 0)' >/dev/null 2>&1 ;;
	cursor) printf '%s' "$2" | jq -e '.permission == "deny" and (.agent_message | length > 0)' >/dev/null 2>&1 ;;
	windsurf) [ -z "$2" ] ;;
	esac
}

# verdict_ok <harness> <deny|allow>: the last run_guard result is the expected
# verdict. Antigravity exits 0 either way, so its stdout decides.
verdict_ok() {
	local h="$1" want="$2"
	if [ "$want" = deny ]; then
		[ "$GUARD_CODE" -eq "$(deny_code "$h")" ] || return 1
		[ "$h" != antigravity ] || printf '%s' "$GUARD_OUT" | grep -q '"decision":"deny"'
	else
		[ "$GUARD_CODE" -eq 0 ] || return 1
		if printf '%s' "$GUARD_OUT" | grep -q 'deny'; then return 1; fi
		case "$h" in
		antigravity | gemini) printf '%s' "$GUARD_OUT" | grep -q '"decision":"allow"' ;;
		*) return 0 ;;
		esac
	fi
}
