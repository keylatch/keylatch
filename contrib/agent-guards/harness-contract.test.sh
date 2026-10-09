#!/usr/bin/env bash
# Per-harness contract test: a denied command, sent in each harness's real
# hook payload, must exit 2 with that harness's deny JSON; an allowed command
# must exit 0 and never emit a deny.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=harness-fixtures.sh
. "$SCRIPT_DIR/harness-fixtures.sh"

PASS=0
FAIL=0

ok() {
	echo "PASS: $1"
	PASS=$((PASS + 1))
}

bad() {
	echo "FAIL: $1"
	FAIL=$((FAIL + 1))
}

DENIED="keylatch get clockify api_key"
ALLOWED="echo hello"

for h in $HARNESSES; do
	run_guard "$h" "$(shell_payload "$h" "$DENIED")"
	if [ "$GUARD_CODE" -eq 2 ] && [ -n "$GUARD_ERR" ] && deny_json_ok "$h" "$GUARD_OUT"; then
		ok "$h: denied command exits 2 with deny contract"
	else
		bad "$h: denied command (code=$GUARD_CODE out=$GUARD_OUT err=$GUARD_ERR)"
	fi

	run_guard "$h" "$(shell_payload "$h" "$ALLOWED")"
	if [ "$GUARD_CODE" -eq 0 ] && ! printf '%s' "$GUARD_OUT" | grep -q 'deny'; then
		ok "$h: allowed command exits 0"
	else
		bad "$h: allowed command (code=$GUARD_CODE out=$GUARD_OUT)"
	fi
done

# Read-tool payloads for harnesses that hook file reads.
for h in claude-code codex gemini copilot; do
	run_guard "$h" "$(read_payload "$h" "/home/dev/.keylatch/vault/imports/plaintext.env")"
	if [ "$GUARD_CODE" -eq 2 ] && deny_json_ok "$h" "$GUARD_OUT"; then
		ok "$h: read of keylatch state exits 2 with deny contract"
	else
		bad "$h: read of keylatch state (code=$GUARD_CODE out=$GUARD_OUT)"
	fi
	run_guard "$h" "$(read_payload "$h" "/work/src/main.go")"
	if [ "$GUARD_CODE" -eq 0 ]; then
		ok "$h: read of a project file exits 0"
	else
		bad "$h: read of a project file (code=$GUARD_CODE)"
	fi
done

# Copilot's camelCase event carries toolArgs as a JSON string.
run_guard copilot "$(copilot_camel_payload "$DENIED")"
if [ "$GUARD_CODE" -eq 2 ] && deny_json_ok copilot "$GUARD_OUT"; then
	ok "copilot: camelCase payload denied"
else
	bad "copilot: camelCase payload (code=$GUARD_CODE out=$GUARD_OUT)"
fi
run_guard copilot "$(copilot_camel_payload "$ALLOWED")"
if [ "$GUARD_CODE" -eq 0 ]; then
	ok "copilot: camelCase allowed command exits 0"
else
	bad "copilot: camelCase allowed command (code=$GUARD_CODE)"
fi

# Gemini requires stdout to be JSON only.
run_guard gemini "$(shell_payload gemini "$ALLOWED")"
if printf '%s' "$GUARD_OUT" | jq -e '.decision == "allow"' >/dev/null 2>&1; then
	ok "gemini: allow output is JSON only"
else
	bad "gemini: allow output ($GUARD_OUT)"
fi

# A misconfigured hook must fail closed, not open.
run_guard bogus "$(shell_payload claude-code "$ALLOWED")"
if [ "$GUARD_CODE" -eq 2 ]; then
	ok "unknown harness exits 2"
else
	bad "unknown harness (code=$GUARD_CODE)"
fi

# The embedded copy must stay byte-identical to the contrib script.
INTERNAL_HOOK="$SCRIPT_DIR/../../internal/guard/scripts/block-keylatch-exfiltration.sh"
if [ -f "$INTERNAL_HOOK" ]; then
	if diff -q "$INTERNAL_HOOK" "$HOOK" >/dev/null 2>&1; then
		ok "internal/contrib copy-sync (byte-identical)"
	else
		bad "internal/contrib copy-sync (files have drifted apart)"
	fi
fi

echo
echo "Harness contract: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
