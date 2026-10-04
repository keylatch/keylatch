#!/usr/bin/env bash
# Commits a rendered package manifest to a tap or bucket repository.
# Usage: push-package-manifest.sh <owner/repo> <path-in-repo> <file> <tag>
# Env:   PUSH_TOKEN         token with contents:write on <owner/repo>
#        PACKAGE_REPO_BASE  clone base URL (default https://github.com)
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

repo="${1:?usage: push-package-manifest.sh <owner/repo> <path-in-repo> <file> <tag>}"
dest="${2:?usage: push-package-manifest.sh <owner/repo> <path-in-repo> <file> <tag>}"
file="${3:?usage: push-package-manifest.sh <owner/repo> <path-in-repo> <file> <tag>}"
tag="${4:?usage: push-package-manifest.sh <owner/repo> <path-in-repo> <file> <tag>}"
require_tag "$tag"
[[ -n "${PUSH_TOKEN:-}" ]] || die "PUSH_TOKEN is not set"
[[ -f "$file" ]] || die "manifest not found: $file"

checkout=$(mktemp -d)
trap 'rm -rf "$checkout"' EXIT
# The token travels in a per-command header, never in the remote URL or config.
auth="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$PUSH_TOKEN" | base64 -w0)"
git -c http.extraheader="$auth" clone -q --depth 1 "${PACKAGE_REPO_BASE:-https://github.com}/${repo}.git" "$checkout"

cp "$file" "$checkout/$dest"
if [[ -z "$(git -C "$checkout" status --porcelain -- "$dest")" ]]; then
  echo "$repo already points at $tag"
  exit 0
fi
git -C "$checkout" add -- "$dest"
git -C "$checkout" \
  -c user.name="github-actions[bot]" \
  -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  commit -q -m "keylatch ${tag#v}"
git -C "$checkout" -c http.extraheader="$auth" push -q origin HEAD
echo "$repo now points at $tag"
