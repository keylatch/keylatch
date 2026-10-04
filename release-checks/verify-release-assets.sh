#!/usr/bin/env bash
# Fails unless a release directory holds every CLI archive, the checksums
# file, both SBOMs and SLSA provenance, with a valid keyless cosign signature
# on each signed file.
# Usage: verify-release-assets.sh [--presence-only] <dir> <tag>
#   --presence-only  check completeness and checksums without cosign or
#                    slsa-verifier (local dry runs)
# Env:   PROVENANCE_SOURCE  "tag" (default) or "main" for provenance produced
#                           by the attest workflow
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

presence_only=0
if [[ "${1:-}" == "--presence-only" ]]; then
  presence_only=1
  shift
fi
dir="${1:?usage: verify-release-assets.sh [--presence-only] <dir> <tag>}"
tag="${2:?usage: verify-release-assets.sh [--presence-only] <dir> <tag>}"
require_tag "$tag"
[[ -d "$dir" ]] || die "not a directory: $dir"
version="${tag#v}"

archives=()
for platform in "${RELEASE_PLATFORMS[@]}"; do
  ext=tar.gz
  [[ "$platform" == windows_* ]] && ext=zip
  archives+=("keylatch_${version}_${platform}.${ext}")
done
checksums="keylatch-${version}_checksums.txt"
signed=("${archives[@]}" "$checksums" "keylatch-${tag}.cdx.json" "keylatch-${tag}.spdx.json")
provenance="keylatch-${tag}-provenance.intoto.jsonl"

shopt -s nullglob
for optional in "keylatch-${tag}.json" "$dir"/*.AppImage "$dir"/*.deb "$dir"/*.dmg "$dir"/*-setup.exe; do
  optional="${optional#"$dir"/}"
  [[ -f "$dir/$optional" ]] && signed+=("$optional")
done

missing=()
for f in "${signed[@]}"; do
  for want in "$f" "$f.sig" "$f.pem"; do
    [[ -f "$dir/$want" ]] || missing+=("$want")
  done
done
[[ -f "$dir/$provenance" ]] || missing+=("$provenance")
if ((${#missing[@]} > 0)); then
  printf 'missing: %s\n' "${missing[@]}" >&2
  die "release $tag is incomplete (${#missing[@]} missing files)"
fi

for a in "${archives[@]}"; do
  grep -qE "^[0-9a-f]{64}  ${a//./\\.}\$" "$dir/$checksums" || die "$checksums does not list $a"
done
(cd "$dir" && sha256sum --quiet --strict -c "$checksums") || die "checksum mismatch in $dir"

if ((presence_only)); then
  echo "release $tag: ${#signed[@]} signed files and provenance present, checksums match"
  exit 0
fi

for f in "${signed[@]}"; do
  cosign_verify_blob "$dir/$f" || die "cosign signature invalid for $f"
done

source_flag=(--source-tag "$tag")
[[ "${PROVENANCE_SOURCE:-tag}" == "main" ]] && source_flag=(--source-branch main)
for a in "${archives[@]}"; do
  slsa-verifier verify-artifact "$dir/$a" \
    --provenance-path "$dir/$provenance" \
    --source-uri github.com/keylatch/keylatch \
    "${source_flag[@]}" >/dev/null || die "SLSA provenance does not cover $a"
done

echo "release $tag: ${#signed[@]} signatures and provenance for ${#archives[@]} archives verified"
