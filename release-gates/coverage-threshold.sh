#!/usr/bin/env bash
# coverage-threshold.sh — assert per-package Go coverage meets the threshold.
#
# Usage:
#   bash release-gates/coverage-threshold.sh [coverage.out] [--report]
#
# Arguments:
#   coverage.out   Path to the coverage profile (default: coverage.out)
#   --report       Print per-package table even when all packages pass
#
# Environment:
#   COVERAGE_THRESHOLD   Minimum acceptable coverage percentage (default: 85)
#
# Exit codes:
#   0   All non-allowlisted packages meet the threshold
#   1   One or more packages are below the threshold
set -euo pipefail

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
coverage_file=""
report=0

for arg in "$@"; do
  case "$arg" in
    --report) report=1 ;;
    *) coverage_file="$arg" ;;
  esac
done

coverage_file="${coverage_file:-coverage.out}"
allowlist="$(dirname "$0")/coverage-allowlist.txt"
threshold="${COVERAGE_THRESHOLD:-85}"

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
if [[ ! -f "$coverage_file" ]]; then
  echo "ERROR: coverage file not found: $coverage_file" >&2
  echo "       Run: go test -coverprofile=coverage.out ./..." >&2
  exit 1
fi

if [[ ! -f "$allowlist" ]]; then
  echo "ERROR: allowlist file not found: $allowlist" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Require python3 — no graceful fallback under set -euo pipefail.
# ---------------------------------------------------------------------------
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 is required to run the coverage gate." >&2
  echo "Install it: brew install python3 / apt-get install python3" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Use Python to parse coverage.out directly and compute statement-weighted
# per-package coverage, then check against the allowlist.
# ---------------------------------------------------------------------------
python3 - "$coverage_file" "$allowlist" "$threshold" "$report" <<'PYEOF'
import sys
import os
from collections import defaultdict

coverage_file = sys.argv[1]
allowlist_file = sys.argv[2]
threshold = float(sys.argv[3])
do_report = sys.argv[4] == "1"

# Load allowlist
allowlisted = set()
with open(allowlist_file) as f:
    for line in f:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        allowlisted.add(line)

# Parse coverage.out directly — statement-weighted aggregation.
# Format:
#   mode: set
#   github.com/foo/bar/file.go:12.5,14.17 3 1
#   ^--- file:start,end                   ^ ^
#                                   stmts   covered (1=yes, 0=no)
pkg_covered = defaultdict(int)
pkg_total = defaultdict(int)

with open(coverage_file) as f:
    next(f)  # skip "mode: ..." header
    for line in f:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        loc = parts[0]          # "github.com/.../file.go:start,end"
        stmts = int(parts[1])
        covered = int(parts[2]) # 1 = covered, 0 = not covered

        file_path = loc.split(':')[0]  # strip ":start,end"
        pkg = '/'.join(file_path.split('/')[:-1])  # strip filename
        if pkg:
            pkg_total[pkg] += stmts
            if covered > 0:
                pkg_covered[pkg] += stmts

# Evaluate packages
failed_packages = []
report_rows = []

for pkg in sorted(pkg_total.keys()):
    total = pkg_total[pkg]
    pct = (pkg_covered[pkg] / total * 100) if total > 0 else 0.0

    if pkg in allowlisted:
        status = 'SKIP'
    elif pct < threshold:
        status = 'FAIL'
        failed_packages.append(f'{pkg} ({pct:.1f}%)')
    else:
        status = 'PASS'

    report_rows.append((status, pct, pkg))

# Compute total project coverage across all packages
total_stmts = sum(pkg_total.values())
total_covered = sum(pkg_covered.values())
total_pct = (total_covered / total_stmts * 100) if total_stmts > 0 else 0.0

# Output report if requested or if failures exist
if do_report or failed_packages:
    print()
    print(f'Coverage gate — threshold: {threshold:.0f}%')
    print('-' * 70)
    print(f'{"STATUS":<8}  {"COVERAGE":>8}  {"PACKAGE"}')
    print('-' * 70)
    for status, pct, pkg in report_rows:
        print(f'{status:<8}  {pct:>7.1f}%  {pkg}')
    print('-' * 70)
    print(f'Total project coverage: {total_pct:.1f}%')
    print()

if failed_packages:
    print(f'FAILED — the following packages are below {threshold:.0f}%:', file=sys.stderr)
    for pkg in failed_packages:
        print(f'  {pkg}', file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix options:', file=sys.stderr)
    print('  1. Write additional tests for the failing packages.', file=sys.stderr)
    print('  2. Add the package to release-gates/coverage-allowlist.txt with a rationale.', file=sys.stderr)
    sys.exit(1)

print(f'Coverage gate PASSED — all non-allowlisted packages meet {threshold:.0f}% threshold.')
print(f'Total project coverage: {total_pct:.1f}%')
PYEOF
