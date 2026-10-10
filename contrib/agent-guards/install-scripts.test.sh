#!/usr/bin/env bash
# The contrib install.sh scripts: they must register every hook event, quote the
# script path (a HOME with a space), be re-runnable, and replace the entries and
# scripts older versions left behind.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS=0
FAIL=0

check() {
	local label="$1"
	shift
	if "$@" >/dev/null 2>&1; then
		PASS=$((PASS + 1))
	else
		echo "FAIL: $label"
		FAIL=$((FAIL + 1))
	fi
}

TMP_ROOT="$(mktemp -d)"
trap 'rm -rf "$TMP_ROOT"' EXIT
export HOME="$TMP_ROOT/h o me"
mkdir -p "$HOME/.keylatch/hooks" "$HOME/.keylatch/guards" "$HOME/.cursor"
unset COPILOT_HOME

run_install() {
	bash "$SCRIPT_DIR/$1/install.sh" >/dev/null 2>&1
}

# Old per-agent scripts, and the old Cursor settings entry.
for a in codex gemini copilot cursor; do
	: >"$HOME/.keylatch/hooks/$a-guard.sh"
	: >"$HOME/.keylatch/guards/$a-guard.sh"
done
printf '%s' "{\"editor\":\"x\",\"hooks\":{\"PreToolUse\":[{\"matcher\":\"*\",\"hooks\":[{\"type\":\"command\",\"command\":\"$HOME/.keylatch/guards/cursor-guard.sh\"}]}]}}" >"$HOME/.cursor/settings.json"
mkdir -p "$HOME/.codex"
printf '%s' "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\".*\",\"hooks\":[{\"type\":\"command\",\"command\":\"$HOME/.keylatch/guards/codex-guard.sh\"}]}]}}" >"$HOME/.codex/hooks.json"

for a in codex gemini copilot cursor; do
	check "$a: install runs" run_install "$a"
	check "$a: second install runs" run_install "$a"
	check "$a: old script removed" test ! -e "$HOME/.keylatch/hooks/$a-guard.sh" -a ! -e "$HOME/.keylatch/guards/$a-guard.sh"
done

check "cursor: beforeShellExecution registered once" jq -e '.hooks.beforeShellExecution | length == 1' "$HOME/.cursor/hooks.json"
check "cursor: beforeReadFile registered once" jq -e '.hooks.beforeReadFile | length == 1' "$HOME/.cursor/hooks.json"
check "cursor: old settings entry removed" jq -e '(.hooks == null) and .editor == "x"' "$HOME/.cursor/settings.json"
check "codex: old entry replaced" jq -e '[.hooks.PreToolUse[].hooks[].command] | length == 1 and (.[0] | contains("codex-guard.sh") | not)' "$HOME/.codex/hooks.json"

DENY_PAYLOAD='{"tool_name":"Bash","tool_input":{"command":"keylatch get x y"}}'
CURSOR_CMD="$(jq -r '.hooks.beforeShellExecution[0].command' "$HOME/.cursor/hooks.json")"
CODEX_CMD="$(jq -r '.hooks.PreToolUse[0].hooks[0].command' "$HOME/.codex/hooks.json")"
GEMINI_CMD="$(jq -r '.hooks.BeforeTool[0].hooks[0].command' "$HOME/.gemini/settings.json")"
COPILOT_CMD="$(jq -r '.hooks.PreToolUse[0].bash' "$HOME/.copilot/hooks/keylatch-guard.json")"
for cmd in "$CURSOR_CMD" "$CODEX_CMD" "$GEMINI_CMD" "$COPILOT_CMD"; do
	code=0
	printf '%s' "$DENY_PAYLOAD" | sh -c "$cmd" >/dev/null 2>&1 || code=$?
	if [ "$code" -ne 2 ]; then
		echo "FAIL: hook command did not run the guard from a HOME with a space ($cmd, exit $code)"
		FAIL=$((FAIL + 1))
	else
		PASS=$((PASS + 1))
	fi
done

echo "Install scripts: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
