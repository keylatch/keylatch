#!/usr/bin/env bash
# packaging/windows/signtool.sh — Windows code-signing wrapper.
#
# Signs a Windows binary using signtool.exe with an EV certificate
# accessed via a cloud HSM. Credentials are read from environment variables.
#
# Required environment variables:
#   WINDOWS_CERT_THUMBPRINT — SHA-1 thumbprint of the EV certificate
#   WINDOWS_HSM_PIN         — PIN for the HSM token (or empty for CNG-managed certs)
#
# Optional:
#   WINDOWS_TIMESTAMP_URL   — RFC 3161 timestamp server URL
#                             (defaults to DigiCert's public TSA)
#
# Usage (from a Windows CI runner with signtool.exe in PATH):
#   bash packaging/windows/signtool.sh path/to/keylatch-app.exe

set -euo pipefail

TARGET="${1:?Usage: signtool.sh <target-binary>}"
TIMESTAMP_URL="${WINDOWS_TIMESTAMP_URL:-http://timestamp.digicert.com}"

: "${WINDOWS_CERT_THUMBPRINT:?ERROR: WINDOWS_CERT_THUMBPRINT is not set.}"

if [[ ! -f "${TARGET}" ]]; then
  echo "ERROR: target binary not found: ${TARGET}" >&2
  exit 1
fi

echo "Signing ${TARGET} with certificate thumbprint ${WINDOWS_CERT_THUMBPRINT}..."

# Build the signtool command. HSM PIN is passed via /p if set.
SIGNTOOL_ARGS=(
  sign
  /sha1 "${WINDOWS_CERT_THUMBPRINT}"
  /fd sha256
  /tr "${TIMESTAMP_URL}"
  /td sha256
  /v
)

if [[ -n "${WINDOWS_HSM_PIN:-}" ]]; then
  SIGNTOOL_ARGS+=(/p "${WINDOWS_HSM_PIN}")
fi

SIGNTOOL_ARGS+=("${TARGET}")

signtool.exe "${SIGNTOOL_ARGS[@]}"
echo "Signing complete."
