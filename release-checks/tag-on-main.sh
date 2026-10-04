#!/usr/bin/env bash
# Fails unless the commit a release tag points to is reachable from main.
# Usage: tag-on-main.sh <tag> [base-ref]   (base-ref defaults to origin/main)
# The caller fetches base-ref first; this script never touches the network.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

tag="${1:?usage: tag-on-main.sh <tag> [base-ref]}"
base="${2:-origin/main}"
require_tag "$tag"

commit=$(git rev-parse --verify --quiet "refs/tags/${tag}^{commit}") || die "tag $tag not found"
git rev-parse --verify --quiet "${base}^{commit}" >/dev/null || die "base ref $base not found"

if ! git merge-base --is-ancestor "$commit" "$base"; then
  die "tag $tag ($commit) is not on $base; releases are cut only from main"
fi
echo "tag $tag ($commit) is on $base"
