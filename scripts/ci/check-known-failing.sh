#!/usr/bin/env bash
# check-known-failing.sh — the number of security tests marked as known to
# fail may only go down. Fixing one means lowering EXPECTED in the same change.
set -euo pipefail

EXPECTED=13

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

COUNT="$( (grep -r --include='*_test.go' 'KNOWN-FAILING:' internal cmd || true) | wc -l | tr -d ' ')"

if [[ "$COUNT" -gt "$EXPECTED" ]]; then
  echo "check-known-failing: ERROR: $COUNT known-failing security tests, expected at most $EXPECTED — fix the defect instead of marking the test" >&2
  exit 1
fi

if [[ "$COUNT" -lt "$EXPECTED" ]]; then
  echo "check-known-failing: ERROR: $COUNT known-failing security tests, EXPECTED is still $EXPECTED — lower it in scripts/ci/check-known-failing.sh" >&2
  exit 1
fi

echo "check-known-failing: OK — $COUNT known-failing security tests"
