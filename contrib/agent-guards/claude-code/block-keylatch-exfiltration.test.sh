#!/usr/bin/env bash
# Test harness for block-keylatch-exfiltration.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOOK="$SCRIPT_DIR/block-keylatch-exfiltration.sh"

PASS=0
FAIL=0

run_case() {
	local label="$1"
	local tool_name="$2"
	local tool_input="$3"
	local expected_code="$4"

	actual_code=0
	CLAUDE_TOOL_NAME="$tool_name" CLAUDE_TOOL_INPUT="$tool_input" bash "$HOOK" </dev/null 2>/dev/null || actual_code=$?

	if [ "$actual_code" -eq "$expected_code" ]; then
		echo "PASS: $label"
		PASS=$((PASS + 1))
	else
		echo "FAIL: $label (expected=$expected_code, got=$actual_code)"
		FAIL=$((FAIL + 1))
	fi
}

# run_case_stdin exercises the current Claude Code contract: tool call JSON on
# stdin, no CLAUDE_TOOL_* env vars set.
run_case_stdin() {
	local label="$1"
	local json="$2"
	local expected_code="$3"

	actual_code=0
	printf '%s' "$json" | env -u CLAUDE_TOOL_NAME -u CLAUDE_TOOL_INPUT bash "$HOOK" 2>/dev/null || actual_code=$?

	if [ "$actual_code" -eq "$expected_code" ]; then
		echo "PASS: $label"
		PASS=$((PASS + 1))
	else
		echo "FAIL: $label (expected=$expected_code, got=$actual_code)"
		FAIL=$((FAIL + 1))
	fi
}

# Core test cases
run_case "Plain get blocked"                    Bash  "keylatch get clockify api_key"                    2
run_case "get --masked allowed"                 Bash  "keylatch get --masked clockify api_key"           0
run_case "security find-generic-password"       Bash  "security find-generic-password -s keylatch -w"   2
run_case "security find-internet-password"      Bash  "security find-internet-password -s test -w"      2
run_case "op read blocked"                      Bash  "op read op://vault/item/field"                    2
run_case "op item get blocked"                  Bash  "op item get my-item"                              2
run_case "bw get blocked"                       Bash  "bw get item clockify"                             2
run_case "bw list blocked"                      Bash  "bw list items"                                    2
run_case ".keylatch Read blocked"               Read  "~/.keylatch/vault/imports/plaintext.env"          2
run_case "keylatch run -- env blocked"          Bash  "keylatch run openrouter -- env"                   2
run_case "keylatch run -- node allowed"         Bash  "keylatch run openrouter -- node script.js"        0
run_case "keylatch list allowed"                Bash  "keylatch list"                                    0
run_case "cat .env blocked"                     Bash  "cat ~/.keylatch/secrets.env"                      2
run_case "keylatch describe allowed"            Bash  "keylatch describe svc"                            0
run_case "keylatch validate allowed"            Bash  "keylatch validate svc"                            0

# SEC3 quoting variants — single-quote wrapper must not bypass blocks
run_case "get blocked single-quoted"            Bash  "'keylatch get clockify api_key'"                  2
run_case "get blocked double-quoted"            Bash  '"keylatch get clockify api_key"'                  2

# Additional edge cases
run_case "keylatch run -- env with args blocked" Bash "keylatch run openrouter -- env HOME"              2
run_case "keylatch get-masked allowed"          Bash  "keylatch get-masked svc key"                      0
run_case "unrelated command allowed"            Bash  "echo hello"                                       0
run_case "node script allowed"                  Bash  "node index.js"                                    0

# Current Claude Code contract — tool call JSON delivered on stdin
run_case_stdin "stdin: plain get blocked"        '{"tool_name":"Bash","tool_input":{"command":"keylatch get clockify api_key"}}'         2
run_case_stdin "stdin: get --masked allowed"     '{"tool_name":"Bash","tool_input":{"command":"keylatch get --masked clockify api_key"}}' 0
run_case_stdin "stdin: tilde .keylatch Read blocked"    '{"tool_name":"Read","tool_input":{"file_path":"~/.keylatch/vault/imports/plaintext.env"}}' 2
run_case_stdin "stdin: absolute .keylatch Read blocked" '{"tool_name":"Read","tool_input":{"file_path":"/Users/u/.keylatch/vault/imports/plaintext.env"}}' 2
run_case_stdin "stdin: env dump blocked"         '{"tool_name":"Bash","tool_input":{"command":"printenv"}}'                               2
run_case_stdin "stdin: unrelated command allowed" '{"tool_name":"Bash","tool_input":{"command":"echo hello"}}'                            0
run_case_stdin "stdin: unrelated Read allowed"   '{"tool_name":"Read","tool_input":{"file_path":"/tmp/notes.md"}}'                        0
run_case_stdin "stdin: empty payload allowed"    '{}'                                                                                     0

echo ""
echo "Results: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
