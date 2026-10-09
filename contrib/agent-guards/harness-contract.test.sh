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
	if [ "$GUARD_CODE" -eq "$(deny_code "$h")" ] && [ -n "$GUARD_ERR" ] && deny_json_ok "$h" "$GUARD_OUT"; then
		ok "$h: denied command follows the deny contract"
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

# File-read payloads: protected paths, a directory that contains one, and an
# unrelated path.
for h in $HARNESSES; do
	for path in "$HOME/.keylatch/vault/imports/plaintext.env" "$HOME/.keylatch" "$HOME/.ssh/id_ed25519" "$HOME" "$HOME/.local/share/atuin/history.db"; do
		run_guard "$h" "$(read_payload "$h" "$path")"
		if [ "$GUARD_CODE" -eq "$(deny_code "$h")" ] && deny_json_ok "$h" "$GUARD_OUT"; then
			ok "$h: read of $path denied"
		else
			bad "$h: read of $path (code=$GUARD_CODE out=$GUARD_OUT)"
		fi
	done
	run_guard "$h" "$(read_payload "$h" "/work/src/main.go")"
	if [ "$GUARD_CODE" -eq 0 ] && ! printf '%s' "$GUARD_OUT" | grep -q 'deny'; then
		ok "$h: read of a project file allowed"
	else
		bad "$h: read of a project file (code=$GUARD_CODE out=$GUARD_OUT)"
	fi
	run_guard "$h" "$(read_payload "$h" "$HOME/code/project")"
	if [ "$GUARD_CODE" -eq 0 ]; then
		ok "$h: read of a sibling directory allowed"
	else
		bad "$h: read of a sibling directory (code=$GUARD_CODE)"
	fi
done

# Cursor checks every attachment path, not just the file being read.
run_guard cursor "$(cursor_attachment_payload "/work/a.go" "$HOME/.aws/credentials")"
if [ "$GUARD_CODE" -eq 2 ] && deny_json_ok cursor "$GUARD_OUT"; then
	ok "cursor: protected attachment denied"
else
	bad "cursor: protected attachment (code=$GUARD_CODE out=$GUARD_OUT)"
fi
run_guard cursor "$(cursor_attachment_payload "/work/a.go" "/work/b.go")"
if [ "$GUARD_CODE" -eq 0 ]; then
	ok "cursor: unrelated attachment allowed"
else
	bad "cursor: unrelated attachment (code=$GUARD_CODE)"
fi

# Antigravity denies with exit 0 and JSON; the exit status must not be 2.
run_guard antigravity "$(shell_payload antigravity "$DENIED")"
if [ "$GUARD_CODE" -eq 0 ] && printf '%s' "$GUARD_OUT" | jq -e '.decision == "deny"' >/dev/null 2>&1; then
	ok "antigravity: deny is exit 0 plus JSON"
else
	bad "antigravity: deny status (code=$GUARD_CODE out=$GUARD_OUT)"
fi

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
