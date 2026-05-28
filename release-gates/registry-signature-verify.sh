#!/usr/bin/env bash
# Verify that every provider bundle has a valid cosign signature (S7-13 / FIND-008).
#
# Supports two signing modes (EPIC-08 / ADR-001):
#
#   Keyless (default): bundle has <file>.sig + <file>.cert
#     cosign verify-blob --certificate <file>.cert --signature <file>.sig \
#       --certificate-identity-regexp="...publish-registry.yml..." \
#       --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
#
#   Keyed (REGISTRY_COSIGN_USE_KEYED=1): bundle has <file>.sig only
#     cosign verify-blob --key internal/registry/cosign.pub \
#       --signature <file>.sig
#
# Usage:
#   registry-signature-verify.sh [bundles-dir]
#   REGISTRY_COSIGN_USE_KEYED=1 registry-signature-verify.sh [bundles-dir]
#
# Example (keyless, default):
#   registry-signature-verify.sh dist/provider-bundles
#
# Example (keyed):
#   REGISTRY_COSIGN_USE_KEYED=1 registry-signature-verify.sh dist/provider-bundles
#
# Requires: cosign
set -euo pipefail

bundles_dir="${1:-dist/provider-bundles}"

if [[ ! -d "$bundles_dir" ]]; then
  echo "Bundles directory not found: $bundles_dir" >&2
  exit 1
fi

if ! command -v cosign &>/dev/null; then
  echo "cosign not found -- install from https://docs.sigstore.dev/cosign/installation/" >&2
  exit 1
fi

use_keyed="${REGISTRY_COSIGN_USE_KEYED:-0}"
# Resolve cosign.pub relative to the repo root (script may be called from any cwd).
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(dirname "$script_dir")"
cosign_pub="$repo_root/internal/registry/cosign.pub"

failures=0
total=0

for bundle in "$bundles_dir"/*.json; do
  [[ -f "$bundle" ]] || continue
  sig_file="${bundle}.sig"
  cert_file="${bundle}.cert"
  total=$((total + 1))

  if [[ ! -f "$sig_file" ]]; then
    echo "  MISSING signature: $sig_file" >&2
    failures=$((failures + 1))
    continue
  fi

  if [[ "$use_keyed" == "1" ]]; then
    # --- Keyed path ---
    if [[ ! -f "$cosign_pub" ]]; then
      echo "  MISSING public key: $cosign_pub" >&2
      failures=$((failures + 1))
      continue
    fi
    if cosign verify-blob \
        --key "$cosign_pub" \
        --signature "$sig_file" \
        "$bundle" &>/dev/null; then
      echo "  OK (keyed): $(basename "$bundle")"
    else
      echo "  INVALID signature (keyed): $bundle" >&2
      failures=$((failures + 1))
    fi
  else
    # --- Keyless path (default) ---
    if [[ ! -f "$cert_file" ]]; then
      echo "  MISSING certificate for keyless verification: $cert_file" >&2
      echo "  (Run with REGISTRY_COSIGN_USE_KEYED=1 for keyed verification)" >&2
      failures=$((failures + 1))
      continue
    fi
    if cosign verify-blob \
        --certificate "$cert_file" \
        --signature "$sig_file" \
        --certificate-identity-regexp="https://github.com/keylatch/keylatch/.github/workflows/publish-registry.yml@refs/heads/main" \
        --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
        "$bundle" &>/dev/null; then
      echo "  OK (keyless): $(basename "$bundle")"
    else
      echo "  INVALID signature (keyless): $bundle" >&2
      failures=$((failures + 1))
    fi
  fi
done

if [[ "$total" -eq 0 ]]; then
  echo "No bundle JSON files found in $bundles_dir" >&2
  exit 1
fi

if [[ "$failures" -gt 0 ]]; then
  echo "$failures/$total bundle(s) failed signature verification" >&2
  exit 1
fi

mode_label="keyless"
[[ "$use_keyed" == "1" ]] && mode_label="keyed"
echo "==> All $total bundle(s) have valid signatures ($mode_label)"
