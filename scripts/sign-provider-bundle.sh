#!/usr/bin/env bash
# Sign community provider template bundles using cosign.
#
# Signing modes (controlled by REGISTRY_COSIGN_USE_KEYED):
#
#   Default (REGISTRY_COSIGN_USE_KEYED unset or 0):
#     Keyless OIDC signing via Fulcio + Rekor. Produces:
#       <bundle>.sig   -- detached signature
#       <bundle>.cert  -- ephemeral Fulcio certificate (chain of trust)
#     Requires: OIDC token available (GitHub Actions with id-token:write,
#     or `cosign sign-blob --yes` prompts browser flow locally).
#
#   Keyed (REGISTRY_COSIGN_USE_KEYED=1):
#     ECDSA-P256 signing with a long-lived key. Produces:
#       <bundle>.sig   -- detached signature (no certificate)
#     Requires: REGISTRY_COSIGN_PRIVATE_KEY (PEM content, not a file path)
#               REGISTRY_COSIGN_PASSWORD
#
#     One-time local setup (store in Keychain, delete the file):
#       security add-generic-password -s "keylatch-bundle-signing" -a "cosign-key" \
#         -w "$(cat cosign.key)"
#       security add-generic-password -s "keylatch-bundle-signing" -a "cosign-passphrase" \
#         -w "your-passphrase"
#       rm cosign.key
#
#     Sign from Keychain (key never written to disk):
#       REGISTRY_COSIGN_PRIVATE_KEY=$(security find-generic-password \
#         -s "keylatch-bundle-signing" -a "cosign-key" -w) \
#       REGISTRY_COSIGN_PASSWORD=$(security find-generic-password \
#         -s "keylatch-bundle-signing" -a "cosign-passphrase" -w) \
#       REGISTRY_COSIGN_USE_KEYED=1 \
#       bash scripts/sign-provider-bundle.sh dist/provider-bundles/
set -euo pipefail

if ! command -v cosign &>/dev/null; then
  echo "cosign not found -- brew install cosign" >&2
  exit 1
fi

bundles_dir="${1:-dist/provider-bundles}"
if [[ ! -d "$bundles_dir" ]]; then
  echo "Bundles directory not found: $bundles_dir" >&2
  exit 1
fi

use_keyed="${REGISTRY_COSIGN_USE_KEYED:-0}"

if [[ "$use_keyed" == "1" ]]; then
  # --- Keyed ECDSA-P256 path ---
  if [[ -z "${REGISTRY_COSIGN_PRIVATE_KEY:-}" ]]; then
    echo "Error: REGISTRY_COSIGN_PRIVATE_KEY must be set (PEM content, not a file path)" >&2
    exit 1
  fi
  if [[ -z "${REGISTRY_COSIGN_PASSWORD:-}" ]]; then
    echo "Error: REGISTRY_COSIGN_PASSWORD must be set" >&2
    exit 1
  fi

  signed=0
  for bundle in "$bundles_dir"/*.json; do
    [[ -f "$bundle" ]] || continue
    sig_file="${bundle}.sig"
    echo "==> Signing (keyed) $(basename "$bundle")"
    COSIGN_PASSWORD="$REGISTRY_COSIGN_PASSWORD" \
      cosign sign-blob \
        --key env://REGISTRY_COSIGN_PRIVATE_KEY \
        --output-signature "$sig_file" \
        "$bundle"
    signed=$((signed + 1))
    echo "  Signature: $sig_file"
  done

  if [[ "$signed" -eq 0 ]]; then
    echo "No bundle JSON files found in $bundles_dir" >&2
    exit 1
  fi
  echo "==> Signed $signed bundle(s) (keyed)"
else
  # --- Keyless OIDC path (default) ---
  signed=0
  for bundle in "$bundles_dir"/*.json; do
    [[ -f "$bundle" ]] || continue
    sig_file="${bundle}.sig"
    cert_file="${bundle}.cert"
    echo "==> Signing (keyless) $(basename "$bundle")"
    cosign sign-blob --yes \
      --output-signature "$sig_file" \
      --output-certificate "$cert_file" \
      "$bundle"
    signed=$((signed + 1))
    echo "  Signature:   $sig_file"
    echo "  Certificate: $cert_file"
  done

  if [[ "$signed" -eq 0 ]]; then
    echo "No bundle JSON files found in $bundles_dir" >&2
    exit 1
  fi
  echo "==> Signed $signed bundle(s) (keyless)"
fi
