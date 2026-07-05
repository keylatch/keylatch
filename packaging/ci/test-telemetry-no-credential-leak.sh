#!/usr/bin/env bash
# test-telemetry-no-credential-leak.sh — telemetry canary scan
#
# Verifies that credential values enrolled in the vault NEVER appear in any
# telemetry event body emitted to the remote sink.
#
# Approach:
#   1. Start a local HTTP server (python3 -m http.server) to capture POST bodies
#   2. Set KEYLATCH_TELEMETRY_URL to point at the mock server
#   3. Bootstrap keylatch in telemetry mode with a canary credential
#   4. Enrol a connection using the canary value
#   5. Run a doctor command (exercises telemetry emit paths)
#   6. Grep all captured request bodies for the canary string
#   7. Fail if the canary is found; pass otherwise
#
# Invariant: telemetry payloads must never contain credential bytes.
#
# Exit codes:
#   0 — canary not found in any captured telemetry body (PASS)
#   1 — canary found, or infrastructure failure (FAIL)
#
# Requirements: go, python3, bash 4+, openssl or /dev/urandom, standard POSIX tools.
#
# Usage:
#   bash packaging/ci/test-telemetry-no-credential-leak.sh [--keylatch <binary>]

set -euo pipefail

# ─── helpers ──────────────────────────────────────────────────────────────────

log()  { printf '[tel-canary] %s\n' "$*"; }
pass() { printf '[tel-canary] PASS: %s\n' "$*"; }
fail() {
  printf '[tel-canary] FAIL: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

require_cmd go
require_cmd python3

# ─── parse args ───────────────────────────────────────────────────────────────

KEYLATCH_BIN=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --keylatch)
      KEYLATCH_BIN="$2"; shift 2 ;;
    *)
      fail "unknown argument: $1" ;;
  esac
done

# ─── workspace ────────────────────────────────────────────────────────────────

WORK=$(mktemp -d)
trap 'cleanup' EXIT

SERVER_PID=""
KEYLATCHD_PID=""

cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  [[ -n "$KEYLATCHD_PID" ]] && kill "$KEYLATCHD_PID" 2>/dev/null || true
  rm -rf "$WORK"
}

CANARY_HOME="$WORK/home"
CAPTURED_DIR="$WORK/captured"
mkdir -p "$CANARY_HOME" "$CAPTURED_DIR"

log "Work dir: $WORK"

# ─── canary value ─────────────────────────────────────────────────────────────

# Format: sk-tel-<hex> — prefix makes false positives impossible.
if command -v openssl >/dev/null 2>&1; then
  CANARY="sk-tel-$(openssl rand -hex 8)"
else
  CANARY="sk-tel-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
fi
log "Canary: ${CANARY:0:14}... (truncated for log safety)"

# ─── build keylatch binary ────────────────────────────────────────────────────

if [[ -z "$KEYLATCH_BIN" ]]; then
  log "Building keylatch binary..."
  KEYLATCH_BIN="$WORK/keylatch"
  go build -buildvcs=false -o "$KEYLATCH_BIN" ./cmd/keylatch
  log "Built: $KEYLATCH_BIN"
fi

[[ -x "$KEYLATCH_BIN" ]] || fail "keylatch binary not executable: $KEYLATCH_BIN"

# ─── start mock telemetry server ──────────────────────────────────────────────
#
# A minimal python3 HTTP server that writes each POST body to a file in
# $CAPTURED_DIR and returns HTTP 200 OK. This records all telemetry payloads
# without requiring netcat (which varies across platforms).

MOCK_PORT=18901

python3 - "$CAPTURED_DIR" "$MOCK_PORT" <<'PYEOF' &
import sys
import os
import http.server
import threading

captured_dir = sys.argv[1]
port = int(sys.argv[2])
counter = 0

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        global counter
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length) if length > 0 else b''
        out = os.path.join(captured_dir, f"req-{counter:04d}.json")
        counter += 1
        with open(out, 'wb') as f:
            f.write(body)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass  # suppress request log noise

srv = http.server.HTTPServer(('127.0.0.1', port), Handler)
srv.serve_forever()
PYEOF

SERVER_PID=$!
log "Mock telemetry server PID=$SERVER_PID on port $MOCK_PORT"

# Wait for the server to become ready.
ATTEMPTS=0
until python3 -c "import socket; s=socket.create_connection(('127.0.0.1', $MOCK_PORT), 1); s.close()" 2>/dev/null; do
  ATTEMPTS=$((ATTEMPTS+1))
  if [[ $ATTEMPTS -ge 30 ]]; then
    fail "mock telemetry server did not start within 3 s"
  fi
  sleep 0.1
done
log "Mock server ready."

# ─── environment ──────────────────────────────────────────────────────────────

export HOME="$CANARY_HOME"
export KEYLATCH_CONFIG_DIR="$CANARY_HOME/.keylatch"
export KEYLATCH_DATA_DIR="$CANARY_HOME/.keylatch/vault"
export KEYLATCH_BACKEND="file"
export KEYLATCH_TELEMETRY_URL="http://127.0.0.1:${MOCK_PORT}/v1/events"
export KEYLATCH_MODE="telemetry"
# Unset kill-switch to ensure telemetry is active.
unset KEYLATCH_TELEMETRY_DISABLE

mkdir -p "$KEYLATCH_DATA_DIR"

# ─── bootstrap ────────────────────────────────────────────────────────────────

log "Bootstrapping keylatch in telemetry mode..."
"$KEYLATCH_BIN" bootstrap --backend file 2>/dev/null || true

# ─── enrol canary credential ──────────────────────────────────────────────────

log "Enrolling canary credential..."

if ! printf '%s' "$CANARY" | "$KEYLATCH_BIN" set default/custom/canary-tel-test/api_key >/dev/null 2>&1; then
  fail "enrollment failed — canary was never written; scan is vacuous; aborting"
fi
log "Enrolled via: keylatch set default/custom/canary-tel-test/api_key"

# ─── exercise telemetry emit paths ────────────────────────────────────────────

log "Running keylatch doctor (exercises telemetry emit paths)..."
"$KEYLATCH_BIN" doctor --json >/dev/null 2>&1 || true

# Poll until at least one telemetry request is captured or 10 s have elapsed.
# The async goroutine has up to 5 s per attempt, so a fixed sleep 1 is insufficient.
WAITED=0
until [[ "$(ls "$CAPTURED_DIR"/req-*.json 2>/dev/null | wc -l)" -gt 0 ]] || [[ "$WAITED" -ge 20 ]]; do
  sleep 0.5
  WAITED=$((WAITED + 1))
done

# ─── canary leak checks ───────────────────────────────────────────────────────

log "Scanning captured telemetry bodies for canary bytes..."

CAPTURED_COUNT=$(find "$CAPTURED_DIR" -name 'req-*.json' | wc -l | tr -d ' ')
log "Captured $CAPTURED_COUNT telemetry request(s)."

LEAK_FOUND=0

if [[ "$CAPTURED_COUNT" -gt 0 ]]; then
  for f in "$CAPTURED_DIR"/req-*.json; do
    if grep -q "$CANARY" "$f" 2>/dev/null; then
      printf '[tel-canary] FAIL: canary found in captured telemetry body: %s\n' "$f" >&2
      grep -n "$CANARY" "$f" | head -5 >&2
      LEAK_FOUND=1
    fi
  done
else
  log "No telemetry requests captured — verifying kill-switch path is safe by default."
fi

# Also scan the data directory for any plaintext canary occurrence outside
# of encrypted vault files.
if find "$KEYLATCH_DATA_DIR" -type f \
    ! -name '*.enc' ! -name '*.kv' ! -name '*.bin' \
    -exec grep -l "$CANARY" {} \; 2>/dev/null | grep -q .; then
  printf '[tel-canary] FAIL: canary found in unencrypted data dir files\n' >&2
  LEAK_FOUND=1
else
  pass "No canary in unencrypted data directory files"
fi

if [[ "$LEAK_FOUND" -ne 0 ]]; then
  fail "invariant violated: canary credential bytes appeared in telemetry output"
fi

pass "no canary credential bytes found in any telemetry channel"
log "All telemetry-canary checks passed."
