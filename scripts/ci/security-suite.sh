#!/usr/bin/env bash
# security-suite.sh — runs the tests behind the securitysuite build tag and
# writes one result row per test.
# Usage: security-suite.sh [summary-file]
# Exits with the go test status, so a failing security test fails the script.
set -euo pipefail

SUMMARY="${1:-${GITHUB_STEP_SUMMARY:-/dev/stdout}}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

command -v jq >/dev/null || { echo "security-suite: ERROR: jq is required" >&2; exit 2; }

mapfile -t FILES < <(grep -rl --include='*_test.go' '^//go:build.*securitysuite' internal cmd | sort)
if [[ "${#FILES[@]}" -eq 0 ]]; then
  echo "security-suite: ERROR: no test file carries the securitysuite build tag" >&2
  exit 2
fi

mapfile -t PKGS < <(printf '%s\n' "${FILES[@]}" | xargs -n1 dirname | sort -u | sed 's|^|./|')
# Only the tests defined in tagged files run; the untagged tests of the same
# packages already run in the main test job.
RUN="$(sed -n 's/^func \(Test[A-Za-z0-9_]*\)(.*/\1/p' "${FILES[@]}" | grep -vx 'TestMain' | sort -u | paste -sd'|' -)"
if [[ -z "$RUN" ]]; then
  echo "security-suite: ERROR: tagged files define no tests" >&2
  exit 2
fi

RESULTS="$(mktemp)"
ROWS="$(mktemp)"
trap 'rm -f "$RESULTS" "$ROWS"' EXIT

# Two packages at a time keeps peak memory bounded.
STATUS=0
go test -tags securitysuite -count=1 -p 2 -timeout 600s -json \
  -run "^(${RUN})\$" "${PKGS[@]}" >"$RESULTS" || STATUS=$?

MODULE="$(go list -m)"
jq -rRn --arg mod "$MODULE/" '
  [inputs | fromjson? | select(.Action == "pass" or .Action == "fail" or .Action == "skip")] as $events
  | ($events | map(select(.Test != null and (.Test | contains("/") | not)))) as $tests
  | ($tests | map(select(.Action == "fail") | .Package) | unique) as $failing
  | ($events
     | map(select(.Test == null and .Action == "fail" and (.Package as $p | $failing | index($p) | not))
           | . + {Test: "(package did not build or run)"})) as $broken
  | ($tests + $broken)
  | sort_by(.Package, .Test)
  | .[]
  | "| \(.Package | ltrimstr($mod)) | \(.Test) | \(.Action) |"
' "$RESULTS" >"$ROWS"

count() { grep -c "| $1 |\$" "$ROWS" || true; }

{
  echo "## Security suite"
  echo
  echo "$(count pass) passed, $(count fail) failed, $(count skip) skipped across ${#PKGS[@]} packages."
  echo
  echo "| Package | Test | Result |"
  echo "|---|---|---|"
  cat "$ROWS"
} >>"$SUMMARY"

if [[ "$SUMMARY" != "/dev/stdout" ]]; then
  cat "$ROWS"
fi

if [[ ! -s "$ROWS" ]]; then
  echo "security-suite: ERROR: go test reported no results (exit $STATUS)" >&2
  exit 2
fi

exit "$STATUS"
