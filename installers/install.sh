#!/usr/bin/env bash
# Install keylatch (and keylatchd when the archive carries it) from a published
# GitHub release on Linux.
#
# Usage: install.sh --version X.Y.Z [--prefix DIR] [--skip-signature]
#
# The archive is checked against the release checksums file, and that file is
# checked with cosign (keyless, GitHub OIDC) before anything is installed.
# --skip-signature leaves only the checksum check, which proves integrity but
# not that the release pipeline built the archive.
#
# KEYLATCH_RELEASE_BASE_URL overrides the download location (used by the tests).
set -euo pipefail

COSIGN_IDENTITY_REGEXP='^https://github\.com/keylatch/keylatch/\.github/workflows/(release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?|attest-release\.yml@refs/heads/main)$'
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'

die() {
  echo "install: $*" >&2
  exit 1
}

version=""
prefix="${HOME}/.local/bin"
skip_signature=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) version="${2:?--version needs a value}"; shift 2 ;;
    --prefix) prefix="${2:?--prefix needs a value}"; shift 2 ;;
    --skip-signature) skip_signature=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

version="${version#v}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] || die "--version X.Y.Z required (got '${version}')"
[[ "$(uname -s)" == "Linux" ]] || die "this installer supports Linux only"

case "$(uname -m)" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

for tool in curl tar sha256sum install; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
if [[ "$skip_signature" -eq 0 ]]; then
  command -v cosign >/dev/null || die "cosign is required to verify the release; install it or pass --skip-signature"
fi

base_url="${KEYLATCH_RELEASE_BASE_URL:-https://github.com/keylatch/keylatch/releases/download}/v${version}"
archive="keylatch_${version}_linux_${arch}.tar.gz"
sums="keylatch-${version}_checksums.txt"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fetch() {
  curl -fsSL --proto '=https,file' -o "${work}/$1" "${base_url}/$1" || die "download failed: ${base_url}/$1"
}

fetch "$archive"
fetch "$sums"

if [[ "$skip_signature" -eq 0 ]]; then
  fetch "${sums}.sig"
  fetch "${sums}.pem"
  cosign verify-blob \
    --certificate-identity-regexp="$COSIGN_IDENTITY_REGEXP" \
    --certificate-oidc-issuer="$COSIGN_OIDC_ISSUER" \
    --certificate "${work}/${sums}.pem" \
    --signature "${work}/${sums}.sig" \
    "${work}/${sums}" >/dev/null || die "signature check failed for ${sums}"
fi

(cd "$work" && grep -F "  ${archive}" "$sums" | sha256sum --check --strict --status) \
  || die "checksum mismatch or missing entry for ${archive}"

mkdir "${work}/extract"
tar -xzf "${work}/${archive}" -C "${work}/extract"

[[ -f "${work}/extract/keylatch" ]] || die "archive has no keylatch binary"
mkdir -p "$prefix"
install -m 0755 "${work}/extract/keylatch" "${prefix}/keylatch"
if [[ -f "${work}/extract/keylatchd" ]]; then
  install -m 0755 "${work}/extract/keylatchd" "${prefix}/keylatchd"
fi

echo "installed keylatch ${version} to ${prefix}"
