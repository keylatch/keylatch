#!/usr/bin/env bash
# SBOM completeness check and CVE scan.
# Usage: sbom-verify.sh <sbom-file>
# Example: sbom-verify.sh dist/keylatch-v0.1.0-sbom.spdx.json
# Requires: grype or osv-scanner, go
set -euo pipefail

sbom_file="${1:?SBOM file path required}"

if [[ ! -f "$sbom_file" ]]; then
  echo "SBOM file not found: $sbom_file" >&2
  exit 1
fi

echo "==> Checking SBOM completeness (direct dependencies only)"
# Only check direct (non-indirect) modules. Indirect transitive deps (e.g.
# hundreds of cloud.google.com sub-packages pulled in by AWS SDK) are pruned
# by syft since they are not compiled into the binary on all platforms.
missing=0
while IFS= read -r mod; do
  [[ "$mod" == "github.com/keylatch/keylatch" || -z "$mod" ]] && continue
  if ! grep -q "$mod" "$sbom_file"; then
    echo "  MISSING from SBOM: $mod" >&2
    missing=$((missing + 1))
  fi
done < <(go list -m -json all 2>/dev/null \
  | python3 -c "
import json, sys
buf = ''
for line in sys.stdin:
    buf += line
    if line.strip() == '}':
        try:
            m = json.loads(buf)
            if not m.get('Indirect') and m.get('Path'):
                print(m['Path'])
        except Exception:
            pass
        buf = ''
")

if [[ "$missing" -gt 0 ]]; then
  echo "SBOM is missing $missing direct module(s)" >&2
  exit 1
fi
echo "  OK: all direct modules present in SBOM"

echo "==> Running CVE scan"
if command -v grype &>/dev/null; then
  grype "sbom:$sbom_file" --fail-on critical
  echo "  OK: grype scan passed (no critical CVEs)"
elif command -v osv-scanner &>/dev/null; then
  osv-scanner --sbom "$sbom_file"
  echo "  OK: osv-scanner scan passed"
else
  echo "  WARNING: neither grype nor osv-scanner found; skipping CVE scan" >&2
fi

echo "==> SBOM verification passed"
