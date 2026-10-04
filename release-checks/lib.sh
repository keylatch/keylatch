# shellcheck shell=bash disable=SC2034
# Shared constants for the release check scripts. Source, do not execute.

# Signatures come from the tag-triggered release workflow, or from the
# attest workflow dispatched on main for a release that was published unsigned.
COSIGN_IDENTITY_REGEXP='^https://github\.com/keylatch/keylatch/\.github/workflows/(release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?|attest-release\.yml@refs/heads/main)$'
COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'

# Must match the builds and archives in .goreleaser.yml.
RELEASE_PLATFORMS=(darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64)

TAG_PATTERN='^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$'

die() {
  echo "error: $*" >&2
  exit 1
}

require_tag() {
  [[ "$1" =~ $TAG_PATTERN ]] || die "invalid release tag: $1"
}

is_prerelease() {
  [[ "$1" == *-* ]]
}

cosign_verify_blob() {
  local file="$1"
  cosign verify-blob \
    --certificate-identity-regexp="$COSIGN_IDENTITY_REGEXP" \
    --certificate-oidc-issuer="$COSIGN_OIDC_ISSUER" \
    --certificate "${file}.pem" \
    --signature "${file}.sig" \
    "$file" >/dev/null
}
