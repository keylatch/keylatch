#!/usr/bin/env bash
# test-clean-machine-bootstrap.sh
#
# Clean-machine smoke test for the bootstrap onboarding flow.
#
# Verifies the sequential first-run guard behaviour when no prior state exists:
#
#   1. `keylatch run` before bootstrap   → exit 7 + "bootstrap" in output
#   2. `keylatch bootstrap`              → succeeds (exit 0)
#   3. `keylatch run` after bootstrap    → exit 6 + "setup" in output (no connection yet)
#   4. `keylatch setup <provider>`       → succeeds via --stdin (exit 0)
#   5. `keylatch run` after setup        → exit 5 (runtime unavailable) OR exit 0
#
# Each step also checks that there is no panic or nil-pointer output.
#
# Requirements: go (in PATH), bash 4+, standard POSIX tools.
# No real provider credentials or external services are required.
#
# Exit codes:
#   0 — all checks passed
#   1 — a check failed (details printed to stderr)
#
# Usage:
#   bash packaging/ci/test-clean-machine-bootstrap.sh [--keylatch <binary>]
#
# When --keylatch is not provided the script builds the binary from source
# into a temporary directory.

set -euo pipefail

# ─── helpers ──────────────────────────────────────────────────────────────────

log()  { printf '[bootstrap-smoke] %s\n' "$*"; }
fail() { printf '[bootstrap-smoke] FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf '[bootstrap-smoke] PASS: %s\n' "$*"; }

# assert_no_panic checks that the given output does not contain a Go panic or
# nil-pointer dereference. Called after every step.
assert_no_panic() {
  local label="$1"
  local output="$2"
  if printf '%s' "$output" | grep -qiE 'panic|nil pointer'; then
    fail "step '$label': output contains panic/nil-pointer:\n$output"
  fi
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_cmd go

# ─── parse args ───────────────────────────────────────────────────────────────

KEYLATCH_BIN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keylatch)
      KEYLATCH_BIN="$2"
      shift 2
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

# ─── build binary if not provided ─────────────────────────────────────────────

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

if [[ -z "$KEYLATCH_BIN" ]]; then
  log "Building keylatch from source..."
  KEYLATCH_BIN="$WORK_DIR/keylatch"
  # Determine repo root (two dirs up from this script).
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
  go build -o "$KEYLATCH_BIN" "$REPO_ROOT/cmd/keylatch" || fail "go build failed"
  log "Binary: $KEYLATCH_BIN"
fi

# ─── isolated data directory ──────────────────────────────────────────────────

KEYLATCH_DATA_DIR="$(mktemp -d)"
export KEYLATCH_CONFIG_DIR="$KEYLATCH_DATA_DIR"
log "Isolated data directory: $KEYLATCH_DATA_DIR"

# This smoke test drives the bootstrap/onboarding flow with the direct_brokered
# runtime (a raw-credential mode), which is subject to the raw-credential
# session gate. As an automated, non-interactive CI run it is an unverified
# session (no signed ticket, no keylatchd), so opt out of that gate explicitly
# — this test validates onboarding exit codes (7 → 6 → 5/0), not session
# verification (which is covered by dedicated unit/e2e tests).
export KEYLATCH_ALLOW_UNVERIFIED_SESSION=1

# Convenience wrapper: capture both stdout and stderr, allow non-zero exit.
run_keylatch() {
  "$KEYLATCH_BIN" "$@" 2>&1 || true
}

# ─── Step 1: keylatch run before bootstrap → exit 7 + "bootstrap" in output ──

log "Step 1: run before bootstrap (expect exit 7, 'bootstrap' in output)..."
set +e
combined_1="$("$KEYLATCH_BIN" run anthropic --runtime direct_brokered -- echo hi 2>&1)"
exit_1=$?
set -e

assert_no_panic "step-1" "$combined_1"

if [[ "$exit_1" -ne 7 ]]; then
  fail "step 1: expected exit 7 (BootstrapMissing), got $exit_1\nOutput: $combined_1"
fi
if ! printf '%s' "$combined_1" | grep -qi 'bootstrap'; then
  fail "step 1: expected 'bootstrap' in output, got:\n$combined_1"
fi
pass "step 1: exit 7 + 'bootstrap' in output"

# ─── Step 2: keylatch bootstrap → exit 0 ─────────────────────────────────────

log "Step 2: bootstrap (expect exit 0)..."
set +e
combined_2="$("$KEYLATCH_BIN" bootstrap --backend file 2>&1)"
exit_2=$?
set -e

assert_no_panic "step-2" "$combined_2"

if [[ "$exit_2" -ne 0 ]]; then
  fail "step 2: expected exit 0 from bootstrap, got $exit_2\nOutput: $combined_2"
fi
pass "step 2: bootstrap succeeded (exit 0)"

# ─── Step 3: keylatch run after bootstrap (no connection yet) → exit 6 ───────

log "Step 3: run after bootstrap, no connection yet (expect exit 6, 'setup' in output)..."
set +e
combined_3="$("$KEYLATCH_BIN" run anthropic --runtime direct_brokered -- echo hi 2>&1)"
exit_3=$?
set -e

assert_no_panic "step-3" "$combined_3"

if [[ "$exit_3" -ne 6 ]]; then
  fail "step 3: expected exit 6 (SecretNotFound), got $exit_3\nOutput: $combined_3"
fi
if ! printf '%s' "$combined_3" | grep -qi 'setup'; then
  fail "step 3: expected 'setup' in output, got:\n$combined_3"
fi
pass "step 3: exit 6 + 'setup' in output"

# ─── Step 4: keylatch setup anthropic --stdin → exit 0 ───────────────────────

log "Step 4: setup anthropic via --stdin (expect exit 0)..."
set +e
combined_4="$(printf '%s' 'sk-ant-fake-key-for-smoke-test' \
  | "$KEYLATCH_BIN" connect anthropic \
    --non-interactive \
    --no-test \
    --field api_key=@- 2>&1)"
exit_4=$?
set -e

assert_no_panic "step-4" "$combined_4"

if [[ "$exit_4" -ne 0 ]]; then
  fail "step 4: expected exit 0 from connect, got $exit_4\nOutput: $combined_4"
fi
pass "step 4: connect succeeded (exit 0)"

# ─── Step 5: keylatch run after setup → exit 5 or 0 ─────────────────────────

log "Step 5: run after setup (expect exit 5 or 0)..."
set +e
combined_5="$("$KEYLATCH_BIN" run anthropic --runtime direct_brokered --allow echo -- echo hi 2>&1)"
exit_5=$?
set -e

assert_no_panic "step-5" "$combined_5"

if [[ "$exit_5" -ne 5 && "$exit_5" -ne 0 ]]; then
  fail "step 5: expected exit 5 (RuntimeNotAvailable) or 0, got $exit_5\nOutput: $combined_5"
fi
pass "step 5: exit $exit_5 (runtime unavailable or success — acceptable)"

# ─── All steps passed ─────────────────────────────────────────────────────────

log "All bootstrap smoke-test steps passed."
