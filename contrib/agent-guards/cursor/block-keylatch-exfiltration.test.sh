#!/usr/bin/env bash
# Test harness for the Cursor block-keylatch-exfiltration.sh guard.
#
# Regression coverage for the v3 fix: patterns 7 (keylatch run -- env), 8
# (.env files), and 9 (bare env/printenv structural tokenizer) were entirely
# absent from this variant prior to v3, so any form of an environment-variable
# dump -- plain, or wrapped in `bash -c '...'` / `sh -c "..."` quoting --
# went completely undetected regardless of quoting. See the claude-code
# guard's block-keylatch-exfiltration.test.sh and its pattern-9 comments for
# the full design rationale this variant now shares.
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
	CURSOR_TOOL_NAME="$tool_name" CURSOR_TOOL_INPUT="$tool_input" bash "$HOOK" </dev/null 2>/dev/null || actual_code=$?

	if [ "$actual_code" -eq "$expected_code" ]; then
		echo "PASS: $label"
		PASS=$((PASS + 1))
	else
		echo "FAIL: $label (expected=$expected_code, got=$actual_code)"
		FAIL=$((FAIL + 1))
	fi
}

# Core patterns (pre-existing, v2)
run_case "Plain get blocked"                    Bash  "keylatch get clockify api_key"                    2
run_case "get --masked allowed"                 Bash  "keylatch get --masked clockify api_key"           0
run_case "security find-generic-password"       Bash  "security find-generic-password -s keylatch -w"   2
run_case "security find-internet-password"      Bash  "security find-internet-password -s test -w"      2
run_case "op read blocked"                      Bash  "op read op://vault/item/field"                    2
run_case "op item get blocked"                  Bash  "op item get my-item"                              2
run_case "bw get blocked"                       Bash  "bw get item clockify"                             2
run_case "bw list blocked"                      Bash  "bw list items"                                    2
run_case ".keylatch Read blocked"                Read  "~/.keylatch/vault/imports/plaintext.env"          2
run_case "keylatch list allowed"                Bash  "keylatch list"                                    0
run_case "unrelated command allowed"            Bash  "echo hello"                                       0

# Quote-wrapped bypass coverage for the pre-existing patterns (already
# quote-aware; regression pins)
run_case "p1 bash -c wrapped blocked"           Bash  "bash -c 'keylatch get clockify api_key'"          2
run_case "p1 sh -c wrapped blocked"             Bash  'sh -c "keylatch get clockify api_key"'            2
run_case "p2 bash -c wrapped blocked"           Bash  "bash -c 'security find-generic-password -s x -w'" 2

# --- pattern 7 (new in v3): keylatch run -- env ---
run_case "p7 plain blocked"                     Bash  "keylatch run openrouter -- env"                  2
run_case "p7 bash -c wrapped blocked"           Bash  "bash -c 'keylatch run openrouter -- env'"         2
run_case "p7 sh -c wrapped blocked"             Bash  'sh -c "keylatch run openrouter -- env"'           2
run_case "keylatch run -- node allowed"         Bash  "keylatch run openrouter -- node script.js"        0

# --- pattern 8 (extended in v3): cat of .env files ---
run_case "cat .keylatch config blocked"         Bash  "cat ~/.keylatch/config.yaml"                      2
run_case "cat .env blocked"                     Bash  "cat ~/.keylatch/secrets.env"                      2
run_case "cat plain .env blocked"               Bash  "cat secrets.env"                                  2
run_case "p8 bash -c wrapped blocked"           Bash  "bash -c 'cat ~/.keylatch/secrets.env'"            2

# --- pattern 9 (new in v3): bare env / printenv structural analyzer ---
run_case "bare env blocked"                     Bash  "env"                                             2
run_case "bare printenv blocked"                Bash  "printenv"                                         2
run_case "p9 bash -c single-quoted env blocked" Bash  "bash -c 'env'"                                    2
run_case "p9 sh -c double-quoted env blocked"   Bash  'sh -c "env"'                                      2
run_case "p9 prose near-miss allowed"           Bash  "grep -n 'env' settings.json"                      0
run_case "p9 VAR=val env still blocked"         Bash  "FOO=bar env"                                      2

# Copy-sync assertion: the go:embed source of truth (internal/guard/scripts)
# must stay byte-identical to this contrib copy -- this variant has no
# comment-prefix difference to normalize (unlike claude-code's "S0-6 "
# prefix), so a plain byte-for-byte diff applies. This is exactly the check
# that would have caught the internal copy silently drifting at
# keylatch-hook-version 1 while contrib moved to v2 and then v3. PASS-neutral
# if the internal copy is absent (the contrib directory may be vendored
# standalone).
INTERNAL_HOOK="$SCRIPT_DIR/../../../internal/guard/scripts/cursor-guard.sh"
if [ -f "$INTERNAL_HOOK" ]; then
	if diff -q "$INTERNAL_HOOK" "$HOOK" >/dev/null 2>&1; then
		echo "PASS: internal/contrib copy-sync (byte-identical)"
		PASS=$((PASS + 1))
	else
		echo "FAIL: internal/contrib copy-sync (files have drifted apart)"
		FAIL=$((FAIL + 1))
	fi
else
	echo "SKIP: internal/contrib copy-sync (internal copy not present -- standalone contrib checkout)"
fi

echo
echo "Cursor guard: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
