#!/usr/bin/env bash
# Requires bash 4+ for mapfile. On macOS, use /usr/local/bin/bash or brew bash.
# packaging/ci/scan-no-secret-in-storage.sh
#
# S-INV-1 / §8.3 Security scan: verify no credential patterns appear in
# keylatch vault storage or persistent OS storage. After any write operation
# (keylatch set, keylatch connect), the vault directory must contain only
# AEAD ciphertext — never plaintext or base64-encoded secrets.
#
# Scans:
#   vault:   KEYLATCH_VAULT_PATH or ~/.keylatch/vault/ (all files recursively)
#            Also checks base64-encoded form of each canary pattern.
#   macOS:   defaults read com.keylatch.app (NSUserDefaults)
#   Linux:   ~/.config/com.keylatch.app/ and ~/.local/share/com.keylatch.app/
#   Windows: HKCU\Software\Keylatch (via reg query)
#
# Exit 0: no secrets found.
# Exit 1: credential pattern found in storage.
#
# Usage:
#   bash packaging/ci/scan-no-secret-in-storage.sh [repo-root]
#   KEYLATCH_CANARY=<secret> bash packaging/ci/scan-no-secret-in-storage.sh [repo-root]
#
# When KEYLATCH_CANARY is set, the script additionally scans for that exact
# string and its base64 representation in the vault directory.

set -euo pipefail

REPO_ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
PATTERNS_FILE="${REPO_ROOT}/packaging/redaction-patterns.json"

if [[ ! -f "$PATTERNS_FILE" ]]; then
  echo "ERROR: ${PATTERNS_FILE} not found"
  exit 1
fi

# Read patterns from JSON (bash 3-compatible using while + read).
PATTERNS=()
if command -v python3 >/dev/null 2>&1; then
  while IFS= read -r pattern; do
    PATTERNS+=("$pattern")
  done < <(python3 -c "import json,sys; [print(p) for p in json.load(sys.stdin)]" < "$PATTERNS_FILE")
elif command -v jq >/dev/null 2>&1; then
  while IFS= read -r pattern; do
    PATTERNS+=("$pattern")
  done < <(jq -r '.[]' "$PATTERNS_FILE")
else
  # Fallback: hardcoded patterns.
  PATTERNS=("sk-" "ghp_" "github_pat_" "AKIA" "xoxb-" "xoxp-")
fi

ERRORS=0
OS="$(uname -s)"

check_content() {
  local source="$1"
  local content="$2"
  for pattern in "${PATTERNS[@]}"; do
    if echo "$content" | grep -qF "$pattern"; then
      echo "ERROR: credential pattern '${pattern}' found in ${source}"
      ERRORS=$((ERRORS + 1))
    fi
  done
}

# ── Vault directory scan (S-INV-1 / T-02-05) ─────────────────────────────────
# Scan the vault data directory for plaintext credential patterns and for any
# canary value set via KEYLATCH_CANARY. AEAD-encrypted files are binary and
# will not match credential patterns; a match means plaintext leaked to disk.
VAULT_DIR="${KEYLATCH_VAULT_PATH:-${HOME}/.keylatch/vault}"
if [[ -d "$VAULT_DIR" ]]; then
  echo "INFO: scanning vault directory: ${VAULT_DIR}"
  while IFS= read -r -d '' file; do
    content=$(cat "$file" 2>/dev/null || true)
    check_content "vault:${file}" "$content"

    # Also check base64-decoded content — some naive encoders write base64 of
    # plaintext rather than AEAD ciphertext (CRIT-01).
    if command -v base64 >/dev/null 2>&1; then
      decoded=$(echo "$content" | base64 --decode 2>/dev/null || true)
      if [[ -n "$decoded" ]]; then
        check_content "vault:${file}(base64-decoded)" "$decoded"
      fi
    fi
  done < <(find "$VAULT_DIR" -type f -print0 2>/dev/null)
else
  echo "INFO: vault directory not found: ${VAULT_DIR} (skipping vault scan)"
fi

# ── Canary-specific scan ──────────────────────────────────────────────────────
# When KEYLATCH_CANARY is set, verify that exact value and its base64 form
# do not appear anywhere in the vault directory (S-INV-1 acceptance criterion).
if [[ -n "${KEYLATCH_CANARY:-}" ]] && [[ -d "$VAULT_DIR" ]]; then
  echo "INFO: canary scan for KEYLATCH_CANARY in ${VAULT_DIR}"
  CANARY_B64=$(printf '%s' "$KEYLATCH_CANARY" | base64 2>/dev/null || true)

  if grep -rqF "$KEYLATCH_CANARY" "$VAULT_DIR" 2>/dev/null; then
    echo "ERROR: KEYLATCH_CANARY plaintext found in vault — CRIT-01 not fixed"
    ERRORS=$((ERRORS + 1))
  fi

  if [[ -n "$CANARY_B64" ]] && grep -rqF "$CANARY_B64" "$VAULT_DIR" 2>/dev/null; then
    echo "ERROR: KEYLATCH_CANARY base64 found in vault — CRIT-01 not fixed"
    ERRORS=$((ERRORS + 1))
  fi

  if [[ $ERRORS -eq 0 ]]; then
    echo "OK: canary not found in vault (AEAD storage confirmed)"
  fi
fi

# ── macOS ─────────────────────────────────────────────────────────────────────
if [[ "$OS" == "Darwin" ]]; then
  defaults_out=$(defaults read com.keylatch.app 2>/dev/null || echo "")
  if [[ -n "$defaults_out" ]]; then
    check_content "NSUserDefaults(com.keylatch.app)" "$defaults_out"
  else
    echo "INFO: com.keylatch.app NSUserDefaults not found (clean)"
  fi
fi

# ── Linux ─────────────────────────────────────────────────────────────────────
if [[ "$OS" == "Linux" ]]; then
  for dir in \
    "${HOME}/.config/com.keylatch.app" \
    "${HOME}/.local/share/com.keylatch.app" \
    "${XDG_CONFIG_HOME:-${HOME}/.config}/keylatch-app"
  do
    if [[ -d "$dir" ]]; then
      while IFS= read -r -d '' file; do
        content=$(cat "$file" 2>/dev/null || true)
        check_content "${file}" "$content"
      done < <(find "$dir" -type f -print0 2>/dev/null)
    fi
  done
fi

# ── Windows (via WSL or Git Bash) ─────────────────────────────────────────────
if command -v reg.exe >/dev/null 2>&1 || command -v reg >/dev/null 2>&1; then
  REG_CMD=$(command -v reg.exe 2>/dev/null || command -v reg)
  reg_out=$("$REG_CMD" query "HKCU\\Software\\Keylatch" /s 2>/dev/null || echo "")
  if [[ -n "$reg_out" ]]; then
    check_content "HKCU\\Software\\Keylatch registry" "$reg_out"
  fi
fi

if [[ $ERRORS -gt 0 ]]; then
  echo "FAIL: ${ERRORS} credential pattern(s) found in storage. S-INV-1 / §8.3 violation."
  exit 1
fi

echo "OK: no credential patterns in storage (S-INV-1 / §8.3 scan passed)"
