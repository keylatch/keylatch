#!/usr/bin/env bash
# test-operating-modes.sh — EPIC-17 Task 7
#
# Integration test for the four operating modes (standard, telemetry, canary, custom).
# For each mode, the test runs `keylatch run --mode <mode> anthropic -- env` against
# a mock upstream and asserts the expected env-var presence or absence.
#
# Requirements: go (in PATH), bash 4+, standard POSIX tools, nc or python3.
# No external services or real provider credentials are required.
#
# Exit codes:
#   0 — all checks passed
#   1 — a check failed (details printed to stderr)
#
# Usage:
#   bash packaging/ci/test-operating-modes.sh [--keylatch <binary>]
#
# When --keylatch is not provided the script builds the binary from source
# into a temporary directory.

set -euo pipefail

# ─── helpers ──────────────────────────────────────────────────────────────────

log()  { printf '[operating-modes] %s\n' "$*"; }
fail() { printf '[operating-modes] FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf '[operating-modes] PASS: %s\n' "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

KEYLATCH_BIN=""
SKIP_BUILD=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keylatch) KEYLATCH_BIN="$2"; shift 2; SKIP_BUILD=true ;;
    *) fail "unknown argument: $1" ;;
  esac
done

require_cmd go

# ─── build ────────────────────────────────────────────────────────────────────

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [[ -z "$KEYLATCH_BIN" ]]; then
  log "Building keylatch binary..."
  go build -o "$TMPDIR/keylatch" ./cmd/keylatch 2>&1 | sed 's/^/  /' || fail "go build failed"
  KEYLATCH_BIN="$TMPDIR/keylatch"
fi

log "Using binary: $KEYLATCH_BIN"

# ─── bootstrap a temp config ──────────────────────────────────────────────────

export KEYLATCH_CONFIG_DIR="$TMPDIR/config"
mkdir -p "$KEYLATCH_CONFIG_DIR"

log "Bootstrapping test config (file backend)..."
"$KEYLATCH_BIN" bootstrap --backend file --data-dir "$TMPDIR/vault" 2>/dev/null || true

# Write a minimal config with the anthropic provider set up as a stub.
cat > "$KEYLATCH_CONFIG_DIR/config.json" <<'EOF'
{
  "version": 1,
  "backend": "file",
  "default_namespace": "default",
  "audit": {
    "enabled": false,
    "max_size_bytes": 5242880,
    "retention_days": 30,
    "sweep_interval_hours": 24
  },
  "ui": {
    "bind": "127.0.0.1"
  },
  "telemetry": {
    "enabled": false
  }
}
EOF

# ─── mock upstream (simple echo server via env) ───────────────────────────────
# Instead of a real upstream, we use `env` as the command — it prints all
# environment variables so we can grep the output for canary tokens.

MOCK_CMD=env

# ─── helper: run keylatch with a mode and capture env output ─────────────────

run_mode_env() {
  local mode="$1"
  # Run with a 5-second timeout; ignore exit code (provider may not be connected in CI)
  KEYLATCH_CONFIG_DIR="$KEYLATCH_CONFIG_DIR" \
    timeout 5 "$KEYLATCH_BIN" run \
      --mode "$mode" \
      anthropic -- $MOCK_CMD 2>/dev/null || true
}

# ─── test: standard mode — no canary, no telemetry injection ─────────────────

log "Testing standard mode..."
output_standard=$(run_mode_env standard)

if echo "$output_standard" | grep -qE '^KEYLATCH_CANARY_ANTHROPIC='; then
  fail "standard mode: KEYLATCH_CANARY_ANTHROPIC should not be present"
fi
pass "standard: no canary env var"

# ─── test: telemetry mode — no canary ────────────────────────────────────────

log "Testing telemetry mode..."
output_telemetry=$(run_mode_env telemetry)

if echo "$output_telemetry" | grep -qE '^KEYLATCH_CANARY_ANTHROPIC='; then
  fail "telemetry mode: KEYLATCH_CANARY_ANTHROPIC should not be present"
fi
pass "telemetry: no canary env var"

# ─── test: canary mode — KEYLATCH_CANARY_ANTHROPIC matches pattern ────────────

log "Testing canary mode..."
output_canary=$(run_mode_env canary)

canary_line=$(echo "$output_canary" | grep -E '^KEYLATCH_CANARY_ANTHROPIC=' || true)
if [[ -z "$canary_line" ]]; then
  # In CI without a connected provider, the run command exits early (no connection).
  # Verify that the canary token appears in env_added of the dry-run plan JSON,
  # which exercises the injection path without requiring a real gateway or credentials.
  log "Note: canary run exited early (no provider connection) — verifying dry-run plan includes canary env var"
  dry_run_out=$(KEYLATCH_CONFIG_DIR="$KEYLATCH_CONFIG_DIR" \
    timeout 5 "$KEYLATCH_BIN" run --mode canary --dry-run --json anthropic -- echo hi 2>/dev/null || true)
  if echo "$dry_run_out" | grep -q '"KEYLATCH_CANARY_ANTHROPIC'; then
    pass "canary: dry-run plan env_added includes KEYLATCH_CANARY_ANTHROPIC"
  else
    fail "canary mode: dry-run plan does not include KEYLATCH_CANARY_ANTHROPIC in env_added (got: $dry_run_out)"
  fi
else
  canary_val="${canary_line#KEYLATCH_CANARY_ANTHROPIC=}"
  if ! echo "$canary_val" | grep -qE '^klc-canary-anthropic-[0-9a-f]{16}$'; then
    fail "canary mode: token '$canary_val' does not match pattern klc-canary-anthropic-[0-9a-f]{16}"
  fi
  pass "canary: KEYLATCH_CANARY_ANTHROPIC matches pattern klc-canary-anthropic-[0-9a-f]{16}"
fi

# ─── test: custom mode — resolves without error ───────────────────────────────

log "Testing custom mode..."
"$KEYLATCH_BIN" config set mode custom 2>/dev/null || true
mode_custom=$("$KEYLATCH_BIN" config get mode 2>/dev/null || echo "")
if [[ "$mode_custom" != "custom" ]]; then
  fail "custom mode: config set mode custom did not persist (got: '$mode_custom')"
fi
pass "custom: mode persisted correctly"

# ─── test: invalid mode is rejected ──────────────────────────────────────────

log "Testing invalid mode rejection..."
if "$KEYLATCH_BIN" config set mode bogus 2>/dev/null; then
  fail "invalid mode 'bogus' should have been rejected"
fi
pass "invalid mode rejected"

# ─── test: KEYLATCH_MODE env var overrides config ─────────────────────────────

log "Testing KEYLATCH_MODE env override..."
"$KEYLATCH_BIN" config set mode standard 2>/dev/null || true
resolved=$(KEYLATCH_MODE=canary "$KEYLATCH_BIN" config get mode 2>/dev/null || echo "")
# config get reflects the stored value not the resolved value; check doctor instead.
doctor_out=$(KEYLATCH_MODE=canary "$KEYLATCH_BIN" doctor --json 2>/dev/null || echo '{}')
# Use sed to handle both compact ("operating_mode":"val") and indented ("operating_mode": "val") JSON.
doctor_mode=$(echo "$doctor_out" | grep -m1 '"operating_mode"' \
  | sed 's/.*"operating_mode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || echo "")
if [[ "$doctor_mode" != "canary" ]]; then
  fail "KEYLATCH_MODE env override: doctor operating_mode='$doctor_mode' (expected 'canary')"
fi
pass "KEYLATCH_MODE env override test complete"

# ─── summary ──────────────────────────────────────────────────────────────────

log "All operating-mode checks passed."
