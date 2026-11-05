#!/usr/bin/env bash
# Fails unless total statement coverage and every package's coverage meet the
# floors in coverage-floors.txt.
# Usage: coverage-threshold.sh [--report] [--floors <file>] [coverage.out]
#   --report  print the per-package table even when every floor is met
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
floors="$here/coverage-floors.txt"
profile=coverage.out
report=0
while (($#)); do
  case "$1" in
    --report) report=1 ;;
    --floors)
      floors="${2:?--floors needs a file}"
      shift
      ;;
    -*) die "unknown option: $1" ;;
    *) profile="$1" ;;
  esac
  shift
done

[[ -f "$profile" ]] || die "coverage profile not found: $profile (run: go test -coverprofile=coverage.out ./...)"
[[ -f "$floors" ]] || die "floors file not found: $floors"
command -v python3 >/dev/null || die "python3 is required"
module=$(awk '$1 == "module" { print $2; exit }' "$here/../go.mod")
[[ -n "$module" ]] || die "cannot read the module path from go.mod"

python3 - "$profile" "$floors" "$module" "$report" <<'PY'
import sys
from collections import defaultdict

profile, floors_file, module, report = sys.argv[1], sys.argv[2], sys.argv[3] + "/", sys.argv[4] == "1"
errors = []


def pct(value, where):
    try:
        f = float(value)
    except ValueError:
        f = -1
    if not 0 <= f <= 100:
        errors.append(f"{where}: floor must be a number from 0 to 100, got {value!r}")
    return f


total_floor = None
default_floor = None
floors = {}
exempt = {}
with open(floors_file) as fh:
    for n, raw in enumerate(fh, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        where = f"{floors_file}:{n}"
        parts = line.split()
        key = parts[0]
        if key in ("total", "default"):
            if len(parts) != 2:
                errors.append(f"{where}: expected '{key} <percent>'")
                continue
            if key == "total":
                total_floor = pct(parts[1], where)
            else:
                default_floor = pct(parts[1], where)
        elif len(parts) >= 2 and parts[1] == "exempt":
            if len(parts) < 3:
                errors.append(f"{where}: exemption for {key} needs a reason")
            if key.endswith("/..."):
                errors.append(f"{where}: exemptions name one package, not a pattern")
            exempt[key] = " ".join(parts[2:])
        elif len(parts) == 2:
            if key in floors:
                errors.append(f"{where}: duplicate floor for {key}")
            floors[key] = pct(parts[1], where)
        else:
            errors.append(f"{where}: expected '<package> <percent>' or '<package> exempt <reason>'")
if total_floor is None:
    errors.append(f"{floors_file}: missing 'total <percent>'")
if default_floor is None:
    errors.append(f"{floors_file}: missing 'default <percent>'")
if errors:
    sys.exit("\n".join(f"error: {e}" for e in errors))

blocks = {}
with open(profile) as fh:
    header = fh.readline()
    if not header.startswith("mode:"):
        errors.append(f"{profile}: not a Go coverage profile")
    for raw in fh:
        parts = raw.split()
        if len(parts) != 3:
            continue
        block, stmts, count = parts[0], int(parts[1]), int(parts[2])
        prev = blocks.get(block)
        blocks[block] = (stmts, max(count, prev[1] if prev else 0))

total = defaultdict(int)
covered = defaultdict(int)
for block, (stmts, count) in blocks.items():
    pkg = block.rsplit(":", 1)[0].rsplit("/", 1)[0]
    pkg = pkg[len(module):] if pkg.startswith(module) else pkg
    total[pkg] += stmts
    if count > 0:
        covered[pkg] += stmts
if not total:
    errors.append(f"{profile}: no coverage blocks")


def matches(key, pkg):
    if key.endswith("/..."):
        return pkg == key[:-4] or pkg.startswith(key[:-3])
    return key == pkg


def floor_for(pkg):
    hits = [k for k in floors if matches(k, pkg)]
    used.update(hits)
    if pkg in floors:
        return floors[pkg]
    return floors[max(hits, key=len)] if hits else default_floor


used = set()
rows = []
for pkg in sorted(total):
    p = 100 * covered[pkg] / total[pkg] if total[pkg] else 100.0
    if pkg in exempt:
        used.add(pkg)
        rows.append(("EXEMPT", p, None, pkg))
        continue
    floor = floor_for(pkg)
    status = "PASS" if p >= floor else "FAIL"
    if status == "FAIL":
        errors.append(f"{pkg}: {p:.1f}% is below its {floor:g}% floor")
    rows.append((status, p, floor, pkg))
for key in sorted(set(floors) | set(exempt)):
    if key not in used:
        errors.append(f"{floors_file}: {key} matches no package in the profile")

all_total = sum(total.values())
all_covered = sum(covered.values())
overall = 100 * all_covered / all_total if all_total else 0.0
if total_floor is not None and overall < total_floor:
    errors.append(f"total: {overall:.1f}% is below the {total_floor:g}% floor")

if errors or report:
    print(f"{'STATUS':<7} {'COVER':>6} {'FLOOR':>6}  PACKAGE")
    for status, p, floor, pkg in rows:
        floor_txt = "-" if floor is None else f"{floor:g}%"
        print(f"{status:<7} {p:5.1f}% {floor_txt:>6}  {pkg}")
print(f"total coverage {overall:.1f}% ({all_covered}/{all_total} statements), floor {total_floor:g}%")
if errors:
    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    sys.exit(1)
print("coverage floors met")
PY
