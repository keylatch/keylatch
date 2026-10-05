#!/usr/bin/env bash
set -euo pipefail

DOCS_DIR="${DOCS_DIR:-docs/}"
EXAMPLES_DIR="examples/"

# ------------------------------------------------------------
# Parse flags
# ------------------------------------------------------------
REPORT_MODE=0
for arg in "$@"; do
  case "$arg" in
    --report) REPORT_MODE=1 ;;
    *) echo "Unknown flag: $arg" >&2; exit 1 ;;
  esac
done

FAILED=0

# ------------------------------------------------------------
# 1. Security checks (path leaks, token patterns)
# ------------------------------------------------------------
for DIR in "$DOCS_DIR" "$EXAMPLES_DIR"; do
  [[ -d "$DIR" ]] || continue

  # Home paths — flag leaked personal home dirs (/Users/<name>, /home/<name>),
  # but allow the documented distroless container home /home/nonroot, which is
  # the image's baked-in KEYLATCH_CONFIG_DIR location, not a leak.
  if grep -rE "/Users/[^/]+|/home/[^/]+" "$DIR" 2>/dev/null | grep -vE "/home/nonroot(/|\b)"; then
    if [[ "$REPORT_MODE" -eq 1 ]]; then
      printf "  FAIL  %-45s (home path leak)\n" "$DIR"
    else
      echo "[PATH LEAK] home paths found in $DIR" >&2
    fi
    FAILED=1
  fi

  # Token patterns (excluding lines with "canary")
  if grep -rE "sk-[A-Za-z0-9]{32,}" "$DIR" 2>/dev/null | grep -iv "canary"; then
    if [[ "$REPORT_MODE" -eq 1 ]]; then
      printf "  FAIL  %-45s (token leak)\n" "$DIR"
    else
      echo "[TOKEN LEAK] token patterns found in $DIR" >&2
    fi
    FAILED=1
  fi
done

# ------------------------------------------------------------
# 2. Required documentation pages
# Each entry: path|minimum_bytes|label
# ------------------------------------------------------------
MIN_BYTES=200

REQUIRED_DOCS=(
  "docs/proxy.md|${MIN_BYTES}|Proxy"
  "docs/call.md|${MIN_BYTES}|Call"
  "docs/operating-modes.md|${MIN_BYTES}|Operating Modes"
  "docs/scripting.md|${MIN_BYTES}|Scripting"
  "docs/architecture/audit-log.md|${MIN_BYTES}|Architecture: Audit Log"
  "docs/cli/environment.md|${MIN_BYTES}|CLI: Environment Variables"
  "docs/telemetry.md|${MIN_BYTES}|Telemetry"
  "docs/experimental.md|${MIN_BYTES}|Experimental"
  "docs/architecture/registry-signing.md|${MIN_BYTES}|Architecture: Registry Signing"
  "docs/verifying-releases.md|${MIN_BYTES}|Verifying Releases"
  "docs/configuration.md|${MIN_BYTES}|Configuration"
  "docs/approval.md|${MIN_BYTES}|Approval"
  "docs/desktop-app.md|${MIN_BYTES}|Desktop App"
  "docs/desktop-parity.md|${MIN_BYTES}|Desktop Parity"
)

check_doc() {
  local entry="$1"
  local path min_bytes label
  IFS='|' read -r path min_bytes label <<< "$entry"

  if [[ ! -f "$path" ]]; then
    if [[ "$REPORT_MODE" -eq 1 ]]; then
      printf "  FAIL  %-45s (missing)\n" "$path"
    else
      echo "[MISSING] $path ($label)" >&2
      FAILED=1
    fi
    return
  fi

  local size
  size=$(wc -c < "$path")
  if [[ "$size" -lt "$min_bytes" ]]; then
    if [[ "$REPORT_MODE" -eq 1 ]]; then
      printf "  FAIL  %-45s (${size} bytes < ${min_bytes} required)\n" "$path"
    else
      echo "[STUB] $path ($label) — ${size} bytes (need >= ${min_bytes})" >&2
      FAILED=1
    fi
    return
  fi

  if [[ "$REPORT_MODE" -eq 1 ]]; then
    printf "  pass  %-45s (${size} bytes)\n" "$path"
  fi
}

if [[ "$REPORT_MODE" -eq 1 ]]; then
  echo ""
  echo "docs-scan: required pages"
  echo "-------------------------------------------"
fi

for entry in "${REQUIRED_DOCS[@]}"; do
  check_doc "$entry"
done

# ------------------------------------------------------------
# Result
# ------------------------------------------------------------
if [[ "$REPORT_MODE" -eq 1 ]]; then
  echo ""
  if [[ "$FAILED" -ne 0 ]]; then
    echo "docs-scan: some checks FAILED (non-fatal in --report mode)"
  else
    echo "docs-scan: all checks passed"
  fi
  exit 0
fi

if [[ "$FAILED" -ne 0 ]]; then
  exit 1
fi

echo "docs-scan: all checks passed"
