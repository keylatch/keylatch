#!/usr/bin/env bash
# Stamp the release version into every manifest that carries one.
#
# The git tag is the only version source. The Go binary receives it through
# ldflags (or build info); the desktop shell and the web package carry a
# placeholder in the repository and are stamped here by the release job.
#
# Usage: scripts/set-version.sh <version|tag> [repo-root]
#        scripts/set-version.sh --check [repo-root]   (all manifests must hold the placeholder)
set -euo pipefail

PLACEHOLDER="0.0.0"

mode=stamp
if [[ "${1:-}" == "--check" ]]; then
  mode=check
  shift
fi

if [[ "$mode" == "stamp" ]]; then
  raw="${1:?usage: set-version.sh <version|tag> [repo-root]}"
  shift
  version="${raw#v}"
  if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]; then
    echo "set-version: '$raw' is not a semantic version" >&2
    exit 2
  fi
fi

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
tauri_conf="$root/src-tauri/tauri.conf.json"
cargo_toml="$root/src-tauri/Cargo.toml"
cargo_lock="$root/src-tauri/Cargo.lock"
web_pkg="$root/web/package.json"

json_version() { jq -r '.version' "$1"; }
toml_version() { awk '/^\[package\]/{p=1;next} /^\[/{p=0} p&&/^version[[:space:]]*=/{gsub(/.*=[[:space:]]*"|".*/,"");print;exit}' "$1"; }
lock_version() { awk '/^name = "keylatch-app"$/{f=1;next} f&&/^version = /{gsub(/.*= "|"/,"");print;exit}' "$1"; }

if [[ "$mode" == "check" ]]; then
  status=0
  for pair in "tauri.conf.json:$(json_version "$tauri_conf")" \
    "Cargo.toml:$(toml_version "$cargo_toml")" \
    "Cargo.lock:$(lock_version "$cargo_lock")" \
    "web/package.json:$(json_version "$web_pkg")"; do
    if [[ "${pair#*:}" != "$PLACEHOLDER" ]]; then
      echo "set-version: ${pair%%:*} holds ${pair#*:}, expected placeholder $PLACEHOLDER" >&2
      status=1
    fi
  done
  exit "$status"
fi

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

stamp_json() {
  jq --arg v "$version" '.version = $v' "$1" >"$tmp"
  cat "$tmp" >"$1"
}

stamp_json "$tauri_conf"
stamp_json "$web_pkg"

awk -v v="$version" '
  /^\[package\]/ { p=1 }
  /^\[/ && !/^\[package\]/ { p=0 }
  p && !done && /^version[[:space:]]*=/ { print "version = \"" v "\""; done=1; next }
  { print }
' "$cargo_toml" >"$tmp"
cat "$tmp" >"$cargo_toml"

awk -v v="$version" '
  /^name = "keylatch-app"$/ { f=1; print; next }
  f && /^version = / { print "version = \"" v "\""; f=0; next }
  { print }
' "$cargo_lock" >"$tmp"
cat "$tmp" >"$cargo_lock"

echo "set-version: stamped $version"
