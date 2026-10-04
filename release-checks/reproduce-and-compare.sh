#!/usr/bin/env bash
# Rebuilds every Go binary inside a published release's archives from the
# tagged source, using the toolchain and flags recorded in each binary's build
# info, and compares SHA-256 digests. Non-binary archive members are compared
# with the same file in the source tree.
#
# Usage: reproduce-and-compare.sh <published-dir> <tag> [source-dir]
#        reproduce-and-compare.sh --self-test
# Exit:  0 every member matches, 1 a digest differs, 2 usage or setup error.
#
# Binaries built without -trimpath embed the build directory, so the rebuild
# has to run from the same absolute path the release was built in (the
# GitHub Actions checkout path).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here/lib.sh"

fail_setup() {
  echo "error: $*" >&2
  exit 2
}

extract() {
  local archive="$1" dest="$2"
  mkdir -p "$dest"
  case "$archive" in
    *.tar.gz) tar -xzf "$archive" -C "$dest" ;;
    *.zip) unzip -q "$archive" -d "$dest" ;;
    *) fail_setup "unsupported archive type: $archive" ;;
  esac
}

rebuild() {
  local binary="$1" source="$2" out="$3" info gover local_gover toolchain revision pkg
  info=$(go version -m -json "$binary")
  gover=$(jq -r '.GoVersion' <<<"$info")
  pkg=$(jq -r '.Path' <<<"$info")
  revision=$(jq -r '.Settings[] | select(.Key == "vcs.revision") | .Value' <<<"$info")
  if [[ -n "$revision" && "$revision" != "$(git -C "$source" rev-parse HEAD)" ]]; then
    echo "built from $revision, source is at $(git -C "$source" rev-parse HEAD)" >&2
    return 1
  fi

  local_gover=$(go env GOVERSION)
  toolchain="$gover"
  [[ "$gover" == "$local_gover" ]] && toolchain=local

  local -a flags=() envs=("GOTOOLCHAIN=$toolchain" "GOFLAGS=")
  while IFS=$'\t' read -r key value; do
    # Build info always records these defaults, but passing -buildmode=exe
    # explicitly changes the linker output.
    case "$key=$value" in
      -buildmode=exe | -compiler=gc) continue ;;
    esac
    case "$key" in
      -*) flags+=("${key}=${value}") ;;
      CGO_* | GO[A-Z0-9]*) envs+=("${key}=${value}") ;;
    esac
  done < <(jq -r '.Settings[] | [.Key, .Value] | @tsv' <<<"$info")

  (cd "$source" && env "${envs[@]}" go build "${flags[@]}" -o "$out" "$pkg")
}

compare_release() (
  local published="$1" tag="$2" source="$3" version sums work mismatches=0
  require_tag "$tag"
  version="${tag#v}"
  sums="$published/keylatch-${version}_checksums.txt"
  [[ -f "$sums" ]] || fail_setup "checksums file not found: $sums"
  (cd "$published" && sha256sum --quiet --strict -c "$(basename "$sums")") \
    || fail_setup "published archives do not match their checksums file"

  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT

  while read -r _ archive; do
    local unpacked="$work/${archive}.d"
    extract "$published/$archive" "$unpacked"
    while IFS= read -r -d '' member; do
      local rel="${member#"$unpacked"/}" want got
      want=$(sha256sum "$member" | cut -d' ' -f1)
      if go version -m "$member" >/dev/null 2>&1; then
        local rebuilt="$work/rebuilt/${archive}/${rel}"
        mkdir -p "$(dirname "$rebuilt")"
        if ! rebuild "$member" "$source" "$rebuilt"; then
          echo "MISMATCH $archive:$rel (rebuild failed)"
          mismatches=$((mismatches + 1))
          continue
        fi
        got=$(sha256sum "$rebuilt" | cut -d' ' -f1)
      elif [[ -f "$source/$rel" ]]; then
        got=$(sha256sum "$source/$rel" | cut -d' ' -f1)
      else
        got=absent
      fi
      if [[ "$want" == "$got" ]]; then
        echo "match    $archive:$rel"
      else
        echo "MISMATCH $archive:$rel published=$want rebuilt=$got"
        mismatches=$((mismatches + 1))
      fi
    done < <(find "$unpacked" -type f -print0 | sort -z)
  done <"$sums"

  if ((mismatches > 0)); then
    echo "$tag: $mismatches archive members differ from the tagged source"
    return 1
  fi
  echo "$tag: every archive member reproduces from the tagged source"
)

self_test() (
  command -v zip >/dev/null || fail_setup "self-test needs zip"
  local root src pub status
  root=$(mktemp -d)
  trap 'rm -rf "$root"' EXIT
  src="$root/src"
  pub="$root/pub"
  mkdir -p "$src" "$pub"

  cat >"$src/go.mod" <<'EOF'
module example.com/fixture

go 1.22
EOF
  cat >"$src/main.go" <<'EOF'
package main

var version = "dev"

func main() { println(version) }
EOF
  echo "fixture license" >"$src/LICENSE"
  git -C "$src" init -q
  git -C "$src" -c user.name=t -c user.email=t@example.com add -A
  git -C "$src" -c user.name=t -c user.email=t@example.com commit -qm fixture
  git -C "$src" tag v1.2.3

  local ldflags="-s -w -X main.version=1.2.3"
  for platform in linux_amd64 windows_amd64; do
    local staging="$root/stage-$platform" bin=keylatch
    [[ "$platform" == windows_* ]] && bin=keylatch.exe
    mkdir -p "$staging"
    (cd "$src" && CGO_ENABLED=0 GOOS="${platform%_*}" GOARCH="${platform#*_}" \
      go build -ldflags="$ldflags" -o "$staging/$bin" .)
    cp "$src/LICENSE" "$staging/"
    if [[ "$platform" == windows_* ]]; then
      (cd "$staging" && zip -q "$pub/keylatch_1.2.3_${platform}.zip" "$bin" LICENSE)
    else
      tar -czf "$pub/keylatch_1.2.3_${platform}.tar.gz" -C "$staging" "$bin" LICENSE
    fi
  done
  (cd "$pub" && sha256sum keylatch_1.2.3_* >keylatch-1.2.3_checksums.txt)

  compare_release "$pub" v1.2.3 "$src" >"$root/match.log" 2>&1 \
    || { cat "$root/match.log"; fail_setup "self-test: identical rebuild reported a mismatch"; }

  echo "changed license" >"$src/LICENSE"
  status=0
  compare_release "$pub" v1.2.3 "$src" >"$root/license.log" 2>&1 || status=$?
  ((status == 1)) || fail_setup "self-test: changed LICENSE not detected"
  git -C "$src" checkout -q -- LICENSE

  echo "// changed" >>"$src/main.go"
  status=0
  compare_release "$pub" v1.2.3 "$src" >"$root/dirty.log" 2>&1 || status=$?
  ((status == 1)) || fail_setup "self-test: uncommitted source change not detected"
  git -C "$src" -c user.name=t -c user.email=t@example.com commit -qam changed
  status=0
  compare_release "$pub" v1.2.3 "$src" >"$root/source.log" 2>&1 || status=$?
  ((status == 1)) || fail_setup "self-test: source change not detected"

  echo "self-test passed: identical rebuild matches; changed files, uncommitted and committed source changes are reported"
)

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit 0
fi
(($# >= 2)) || fail_setup "usage: reproduce-and-compare.sh <published-dir> <tag> [source-dir] | --self-test"
compare_release "$1" "$2" "${3:-.}"
