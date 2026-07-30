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

# Quote-wrapped / subshell-wrapped bypass coverage (SEC3 extended to
# patterns 2-5, 7-9). Confirmed reproduction before the fix: bash -c '...'
# and sh -c "..." wrappers evaded these patterns because the leading
# boundary was whitespace-only, not quote-aware.

# --- pattern 1: keylatch get (already quote-aware; regression coverage) ---
run_case "p1 bash -c wrapped blocked"           Bash  "bash -c 'keylatch get clockify api_key'"          2
run_case "p1 sh -c wrapped blocked"             Bash  'sh -c "keylatch get clockify api_key"'            2
run_case "p1 prose near-miss allowed"           Bash  "echo 'keylatch getSecretValue helper'"            0

# --- pattern 2: security find-generic-password ---
run_case "p2 bash -c wrapped blocked"           Bash  "bash -c 'security find-generic-password -s x -w'" 2
run_case "p2 sh -c wrapped blocked"             Bash  'sh -c "security find-generic-password -s x -w"'   2
run_case "p2 prose near-miss allowed"           Bash  "echo 'security' word alone"                       0

# --- pattern 3: security find-internet-password ---
run_case "p3 bash -c wrapped blocked"           Bash  "bash -c 'security find-internet-password -s x -w'" 2
run_case "p3 sh -c wrapped blocked"             Bash  'sh -c "security find-internet-password -s x -w"'  2
run_case "p3 prose near-miss allowed"           Bash  "echo find-internet-password removed from docs"    0

# --- pattern 4: op read / op item get ---
run_case "p4 bash -c wrapped blocked"           Bash  "bash -c 'op read op://vault/item/field'"          2
run_case "p4 sh -c wrapped blocked"             Bash  'sh -c "op item get my-item"'                      2
run_case "p4 prose near-miss allowed"           Bash  "echo 'op' is a great cli, read the docs"          0

# --- pattern 5: bw get / bw list ---
run_case "p5 bash -c wrapped blocked"           Bash  "bash -c 'bw get item clockify'"                   2
run_case "p5 sh -c wrapped blocked"             Bash  'sh -c "bw list items"'                            2
run_case "p5 prose near-miss allowed"           Bash  "echo 'bw' tool notes"                             0

# --- pattern 7: keylatch run -- env ---
run_case "p7 bash -c wrapped blocked"           Bash  "bash -c 'keylatch run openrouter -- env'"         2
run_case "p7 sh -c wrapped blocked"             Bash  'sh -c "keylatch run openrouter -- env"'           2
run_case "p7 prose near-miss allowed"           Bash  "echo keylatch run supports -- environment flags"  0

# --- pattern 8: cat of keylatch/.env paths (the confirmed bypass repro) ---
run_case "p8 bash -c wrapped blocked (repro)"   Bash  "bash -c 'cat ~/.keylatch/secrets.env'"            2
run_case "p8 sh -c wrapped blocked (repro)"     Bash  'sh -c "cat ~/.keylatch/secrets.env"'              2
run_case "p8 prose near-miss allowed"           Bash  "grep -n keylatch README.md"                       0

# --- pattern 9: bare env / printenv (command-position anchor, quote-extended) ---
run_case "p9 bare env blocked"                  Bash  "env"                                              2
run_case "p9 bash -c wrapped blocked"           Bash  "bash -c 'env'"                                    2
run_case "p9 sh -c wrapped blocked"             Bash  'sh -c "printenv"'                                 2
run_case "p9 var-prefixed env blocked"          Bash  "FOO=bar env"                                      2
run_case "p9 prose JSON key allowed"            Bash  "grep -n '\"env\"' settings.json"                  0
run_case "p9 dotenv mention allowed"            Bash  "echo .env.example is our template file"           0
run_case "p9 environment word allowed"          Bash  "cat package.json | grep environment"              0

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
