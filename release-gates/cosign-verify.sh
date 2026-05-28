#!/usr/bin/env bash
# In-pipeline and post-release cosign verification.
# Usage: cosign-verify.sh <version> [dist-dir]
# Example: cosign-verify.sh v1.0.0 dist/
# Requires: cosign, curl (if downloading from GitHub releases)
set -euo pipefail

version="${1:?version required (e.g. v1.0.0)}"
dist_dir="${2:-dist}"

# Discover checksums file dynamically — goreleaser names it
# keylatch-<bare-version>_checksums.txt (no leading 'v').
sums_file=$(find "$dist_dir" -maxdepth 1 -name "*_checksums.txt" | head -1)

if [[ -z "$sums_file" ]]; then
  # Not present in dist/ — try downloading from GitHub releases.
  echo "Checksums file not found in $dist_dir; downloading from GitHub releases..."
  version_bare="${version#v}"
  sums_file="$dist_dir/keylatch-${version_bare}_checksums.txt"
  mkdir -p "$dist_dir"
  base_url="https://github.com/keylatch/keylatch/releases/download/${version}"
  curl -fsSL "$base_url/keylatch-${version_bare}_checksums.txt" -o "$sums_file"
fi

sig_file="${sums_file}.sig"
cert_file="${sums_file}.pem"

if [[ ! -f "$sig_file" ]]; then
  version_bare="${version#v}"
  echo "Signature file not found in $dist_dir; downloading from GitHub releases..."
  curl -fsSL \
    "https://github.com/keylatch/keylatch/releases/download/${version}/keylatch-${version_bare}_checksums.txt.sig" \
    -o "$sig_file"
fi

if [[ ! -f "$cert_file" ]]; then
  version_bare="${version#v}"
  echo "Certificate file not found in $dist_dir; downloading from GitHub releases..."
  curl -fsSL \
    "https://github.com/keylatch/keylatch/releases/download/${version}/keylatch-${version_bare}_checksums.txt.pem" \
    -o "$cert_file"
fi

echo "==> Verifying cosign signature for $version"
cosign verify-blob \
  --certificate-identity-regexp="^https://github\.com/keylatch/keylatch/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate "$cert_file" \
  --signature "$sig_file" \
  "$sums_file"

echo "==> Signature valid for $version"
