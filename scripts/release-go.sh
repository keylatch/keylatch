#!/usr/bin/env bash
# Stand-in for the go binary in .goreleaser.yml. Linux and Windows builds pass
# straight through and stay static. macOS builds need cgo (LocalAuthentication
# for presence), which cannot be cross-compiled from Linux, so the release
# workflow builds them on a macOS runner and this script installs those
# binaries where goreleaser expects its own output.
#
# KEYLATCH_DARWIN_BINARIES holds <goarch>/<binary> files.
set -euo pipefail

if [[ "${1:-}" != "build" || "${GOOS:-}" != "darwin" ]]; then
  exec go "$@"
fi

out=""
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  [[ "${args[i]}" == "-o" ]] && out="${args[i + 1]}"
done
[[ -n "$out" ]] || { echo "release-go: no -o in: $*" >&2; exit 2; }

src="${KEYLATCH_DARWIN_BINARIES:?set KEYLATCH_DARWIN_BINARIES to the macOS build output}/${GOARCH}/$(basename "$out")"
[[ -f "$src" ]] || { echo "release-go: missing macOS binary $src" >&2; exit 1; }
mkdir -p "$(dirname "$out")"
cp "$src" "$out"
