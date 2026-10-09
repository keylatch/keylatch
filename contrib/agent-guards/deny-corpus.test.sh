#!/usr/bin/env bash
# Shared deny corpus: every command here is evaluated through every harness's
# real payload, so the corpus is enforced identically for all agents.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=harness-fixtures.sh
. "$SCRIPT_DIR/harness-fixtures.sh"

PASS=0
FAIL=0

DENY=(
	"env"
	"printenv"
	"bash -c 'env'"
	"keylatch get clockify api_key"
	"cat ~/.keylatch/config.yaml"
	"op read op://vault/item/field"
	"bw get item clockify"
	"direnv exec . env"
	"direnv exec /abs/project printenv"
	"direnv exec . bash -c 'env'"
	"direnv export bash"
	"direnv export json"
	"direnv -v export zsh"
	"direnv dump"
	"mise env"
	"mise env -s bash"
	"mise e"
	"mise exec -- env"
	"mise x node@22 -- printenv"
	"mise set"
	"atuin search foo"
	"atuin search --limit 50"
	"atuin history list"
	"atuin history last"
	"bash -c 'direnv export bash'"
	"sudo mise env"
	"cd /work && direnv export bash"
	"cat ~/.bash_history"
	"tail -n 200 ~/.zsh_history"
	"ls ~/.local/share/atuin"
	"sqlite3 ~/.local/share/atuin/history.db .dump"
)

ALLOW=(
	"echo hello"
	"keylatch get --masked clockify api_key"
	"keylatch list"
	"direnv allow"
	"direnv reload"
	"direnv exec . npm test"
	"direnv exec /abs/project make build"
	"mise install"
	"mise use node@22"
	"mise exec -- node -v"
	"mise x node@22 -- npm test"
	"mise set FOO=bar"
	"mise run build"
	"atuin sync"
	"atuin status"
	"grep -n direnv README.md"
	"echo atuin search"
	"git log --oneline"
)

check() {
	local want="$1" cmd="$2" h
	for h in $HARNESSES; do
		run_guard "$h" "$(shell_payload "$h" "$cmd")"
		want_code="$want"
		[ "$want" -eq 2 ] && want_code="$(deny_code "$h")"
		if [ "$GUARD_CODE" -eq "$want_code" ] && { [ "$want" -ne 2 ] || [ "$h" != antigravity ] || printf '%s' "$GUARD_OUT" | grep -q '"deny"'; }; then
			PASS=$((PASS + 1))
		else
			echo "FAIL: [$h] expected=$want got=$GUARD_CODE: $cmd"
			FAIL=$((FAIL + 1))
		fi
	done
}

for cmd in "${DENY[@]}"; do check 2 "$cmd"; done
for cmd in "${ALLOW[@]}"; do check 0 "$cmd"; done

for h in $HARNESSES; do
	for path in "$HOME/.bash_history" "$HOME/.local/share/atuin/history.db" "$HOME/.keylatch/config.yaml" "$HOME/.ssh" "$HOME"; do
		run_guard "$h" "$(read_payload "$h" "$path")"
		if [ "$GUARD_CODE" -eq "$(deny_code "$h")" ]; then
			PASS=$((PASS + 1))
		else
			echo "FAIL: [$h] read of $path expected=$(deny_code "$h") got=$GUARD_CODE"
			FAIL=$((FAIL + 1))
		fi
	done
done

echo "Deny corpus: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
