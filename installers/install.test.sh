#!/usr/bin/env bash
# Tests installers/install.sh against a fake release served from a local
# directory and a fake cosign. Nothing is downloaded and nothing is installed
# outside a temporary prefix.
# shellcheck disable=SC2016 # the single-quoted bash -c bodies expand in the child shell
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
installer="${here}/install.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

version="0.9.9"
case "$(uname -m)" in
  aarch64 | arm64) arch="arm64" ;;
  *) arch="amd64" ;;
esac
archive="keylatch_${version}_linux_${arch}.tar.gz"
sums="keylatch-${version}_checksums.txt"

release="${work}/releases/v${version}"
mkdir -p "$release" "${work}/pkg" "${work}/bin"
printf '#!/bin/sh\necho keylatch\n' >"${work}/pkg/keylatch"
printf '#!/bin/sh\necho keylatchd\n' >"${work}/pkg/keylatchd"
tar -czf "${release}/${archive}" -C "${work}/pkg" keylatch keylatchd
(cd "$release" && sha256sum "$archive" >"$sums")
printf 'sig' >"${release}/${sums}.sig"
printf 'pem' >"${release}/${sums}.pem"

# The fake cosign records its arguments and succeeds unless told to fail.
cat >"${work}/bin/cosign" <<'EOF'
#!/bin/sh
echo "$@" >>"$COSIGN_LOG"
[ -z "${COSIGN_FAIL:-}" ]
EOF
chmod +x "${work}/bin/cosign"

export COSIGN_LOG="${work}/cosign.log"
export KEYLATCH_RELEASE_BASE_URL="file://${work}/releases"
export PATH="${work}/bin:${PATH}"

failures=0
check() {
  if ! "$@"; then
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
  fi
}

run_installer() {
  bash "$installer" "$@" >"${work}/out" 2>&1
}

# Happy path: signature checked, both binaries installed.
prefix="${work}/prefix1"
check run_installer --version "$version" --prefix "$prefix"
check test -x "${prefix}/keylatch"
check test -x "${prefix}/keylatchd"
check grep -q 'verify-blob' "$COSIGN_LOG"
check grep -q 'certificate-oidc-issuer=https://token.actions.githubusercontent.com' "$COSIGN_LOG"

# A leading v is accepted.
check run_installer --version "v${version}" --prefix "${work}/prefix2"
check test -x "${work}/prefix2/keylatch"

# Tampered archive: refuses and installs nothing.
cp "${release}/${archive}" "${work}/archive.orig"
printf 'tampered' >>"${release}/${archive}"
prefix="${work}/prefix3"
check bash -c '! bash "$0" --version "$1" --prefix "$2" >/dev/null 2>&1' "$installer" "$version" "$prefix"
check test ! -e "${prefix}/keylatch"
cp "${work}/archive.orig" "${release}/${archive}"

# Failed signature: refuses and installs nothing.
prefix="${work}/prefix4"
check env COSIGN_FAIL=1 bash -c '! bash "$0" --version "$1" --prefix "$2" >/dev/null 2>&1' "$installer" "$version" "$prefix"
check test ! -e "${prefix}/keylatch"

# Missing cosign refuses unless --skip-signature is explicit.
no_cosign_path="${work}/nocosign"
mkdir -p "$no_cosign_path"
for t in bash curl tar sha256sum install uname mktemp grep rm mkdir cat dirname gzip; do
  ln -sf "$(command -v "$t")" "${no_cosign_path}/${t}"
done
prefix="${work}/prefix5"
check env PATH="$no_cosign_path" bash -c '! bash "$0" --version "$1" --prefix "$2" >/dev/null 2>&1' "$installer" "$version" "$prefix"
check test ! -e "${prefix}/keylatch"
check env PATH="$no_cosign_path" bash "$installer" --version "$version" --prefix "$prefix" --skip-signature
check test -x "${prefix}/keylatch"

# Input validation.
check bash -c '! bash "$0" --version latest >/dev/null 2>&1' "$installer"
check bash -c '! bash "$0" >/dev/null 2>&1' "$installer"

if [[ "$failures" -ne 0 ]]; then
  echo "${failures} check(s) failed" >&2
  exit 1
fi
echo "install.test.sh: ok"
