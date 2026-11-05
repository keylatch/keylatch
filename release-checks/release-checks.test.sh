#!/usr/bin/env bash
# Offline tests for the release check scripts.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

passed=0
failed=0
expect() {
  local want="$1" name="$2"
  shift 2
  local status=0
  "$@" >"$work/out.log" 2>&1 || status=$?
  if { [[ "$want" == pass ]] && ((status == 0)); } || { [[ "$want" == fail ]] && ((status != 0)); }; then
    passed=$((passed + 1))
  else
    failed=$((failed + 1))
    echo "FAIL: $name (exit $status)"
    sed 's/^/    /' "$work/out.log"
  fi
}

# tag-on-main
repo="$work/repo"
git init -q -b main "$repo"
g() { git -C "$repo" -c user.name=t -c user.email=t@example.com "$@"; }
g commit -q --allow-empty -m base
g tag v1.0.0
g switch -q -c release/v1.0.1
g commit -q --allow-empty -m "release-only fix"
g tag -a v1.0.1 -m annotated
g switch -q main
g commit -q --allow-empty -m later
on_main() { (cd "$repo" && bash "$here/tag-on-main.sh" "$@"); }
expect pass "tag on main" on_main v1.0.0 main
expect fail "tag on release branch" on_main v1.0.1 main
expect fail "unknown tag" on_main v9.9.9 main
expect fail "malformed tag" on_main 1.0.0 main
expect fail "unknown base" on_main v1.0.0 origin/missing

# required-checks-passed
runs="$work/runs"
mkdir -p "$runs"
run() { jq -n --arg c "$1" --arg t "$2" --arg s "${3:-completed}" '{status: $s, conclusion: $c, completed_at: $t}'; }
fixture() {
  local name="$1"
  shift
  jq -s '{check_runs: .}' <(for r in "$@"; do echo "$r"; done) >"$runs/$name.json"
}
fixture a "$(run failure 2026-01-01T00:00:00Z)" "$(run success 2026-01-02T00:00:00Z)"
fixture b "$(run success 2026-01-01T00:00:00Z)" "$(run failure 2026-01-02T00:00:00Z)"
fixture c "$(run null 2026-01-03T00:00:00Z in_progress)" "$(run success 2026-01-01T00:00:00Z)"
fixture d
sha=0123456789abcdef0123456789abcdef01234567
checks() { REQUIRED_CHECKS="$1" CHECK_RUNS_DIR="$runs" bash "$here/required-checks-passed.sh" "$sha"; }
expect pass "latest run succeeded" checks "a"
expect fail "latest run failed" checks "b"
expect pass "in-progress rerun ignored" checks "c"
expect fail "check never ran" checks "d"
expect fail "one of several failed" checks "a b c"
protected_runs="$work/protected-runs"
mkdir -p "$protected_runs"
while IFS= read -r name; do
  jq -s '{check_runs: .}' <(run success 2026-01-01T00:00:00Z) >"$protected_runs/$name.json"
done < <(jq -r '.required_status_checks.contexts[]' "$here/../.github/branch-protection.json")
expect pass "default checks come from branch protection" env CHECK_RUNS_DIR="$protected_runs" bash "$here/required-checks-passed.sh" "$sha"
rm "$protected_runs/coverage.json"
expect fail "coverage is a required check" env CHECK_RUNS_DIR="$protected_runs" bash "$here/required-checks-passed.sh" "$sha"
expect fail "short sha rejected" bash "$here/required-checks-passed.sh" 0123abc

# verify-release-assets and render-package-manifests
tag=v1.2.3
rel="$work/release"
mkdir -p "$rel"
make_release() {
  rm -rf "$rel" && mkdir -p "$rel"
  local p ext
  for p in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64; do
    ext=tar.gz
    [[ $p == windows_* ]] && ext=zip
    echo "$p" >"$rel/keylatch_1.2.3_${p}.${ext}"
  done
  (cd "$rel" && sha256sum keylatch_1.2.3_* >keylatch-1.2.3_checksums.txt)
  echo '{}' >"$rel/keylatch-${tag}.cdx.json"
  echo '{}' >"$rel/keylatch-${tag}.spdx.json"
  echo '{}' >"$rel/keylatch-${tag}-provenance.intoto.jsonl"
  local f
  for f in "$rel"/keylatch_1.2.3_* "$rel"/keylatch-1.2.3_checksums.txt "$rel"/*.cdx.json "$rel"/*.spdx.json; do
    touch "$f.sig" "$f.pem"
  done
}
assets() { bash "$here/verify-release-assets.sh" --presence-only "$rel" "$tag"; }
make_release
expect pass "complete release" assets
rm "$rel/keylatch_1.2.3_linux_arm64.tar.gz.sig"
expect fail "missing archive signature" assets
make_release
rm "$rel/keylatch-${tag}-provenance.intoto.jsonl"
expect fail "missing provenance" assets
make_release
rm "$rel/keylatch-${tag}.spdx.json.pem"
expect fail "missing SPDX certificate" assets
make_release
echo tampered >>"$rel/keylatch_1.2.3_darwin_arm64.tar.gz"
expect fail "archive does not match checksums" assets
make_release
echo '{}' >"$rel/Keylatch_1.2.3_amd64.AppImage"
expect fail "unsigned desktop bundle" assets
touch "$rel/Keylatch_1.2.3_amd64.AppImage.sig" "$rel/Keylatch_1.2.3_amd64.AppImage.pem"
expect pass "signed desktop bundle" assets
echo '{}' >"$rel/keylatch-${tag}.json"
touch "$rel/keylatch-${tag}.json.sig"
expect fail "release manifest without certificate" assets
make_release
expect fail "malformed tag" bash "$here/verify-release-assets.sh" --presence-only "$rel" 1.2.3

out="$work/manifests"
make_release
render() { bash "$here/render-package-manifests.sh" "$tag" "$rel/keylatch-1.2.3_checksums.txt" "$out"; }
expect pass "render manifests" render
formula_ok() {
  local sha
  sha=$(awk '$2 == "keylatch_1.2.3_darwin_arm64.tar.gz" { print $1 }' "$rel/keylatch-1.2.3_checksums.txt")
  grep -q "releases/download/v1.2.3/keylatch_1.2.3_darwin_arm64.tar.gz" "$out/keylatch.rb" &&
    grep -q "sha256 \"$sha\"" "$out/keylatch.rb" &&
    grep -q 'version "1.2.3"' "$out/keylatch.rb"
}
expect pass "formula points at the release" formula_ok
scoop_ok() {
  local sha
  sha=$(awk '$2 == "keylatch_1.2.3_windows_amd64.zip" { print $1 }' "$rel/keylatch-1.2.3_checksums.txt")
  [[ "$(jq -r '.architecture."64bit".hash' "$out/keylatch.json")" == "$sha" ]] &&
    [[ "$(jq -r '.version' "$out/keylatch.json")" == "1.2.3" ]]
}
expect pass "scoop manifest points at the release" scoop_ok
grep -v windows_amd64 "$rel/keylatch-1.2.3_checksums.txt" >"$work/partial.txt"
expect fail "render without windows archive" bash "$here/render-package-manifests.sh" "$tag" "$work/partial.txt" "$work/partial"

# push-package-manifest against a local bare repository
remote="$work/remote"
git init -q --bare -b main "$remote/keylatch/homebrew-tap.git"
seed="$work/seed"
git clone -q "$remote/keylatch/homebrew-tap.git" "$seed" 2>/dev/null
echo old >"$seed/keylatch.rb"
git -C "$seed" -c user.name=t -c user.email=t@example.com add keylatch.rb
git -C "$seed" -c user.name=t -c user.email=t@example.com commit -qm seed
git -C "$seed" push -q origin HEAD:main
push() { PUSH_TOKEN=test PACKAGE_REPO_BASE="file://$remote" bash "$here/push-package-manifest.sh" keylatch/homebrew-tap keylatch.rb "$out/keylatch.rb" "$tag"; }
expect pass "push manifest" push
pushed_ok() { cmp -s <(git -C "$remote/keylatch/homebrew-tap.git" show main:keylatch.rb) "$out/keylatch.rb"; }
expect pass "tap holds the rendered formula" pushed_ok
commits_before=$(git -C "$remote/keylatch/homebrew-tap.git" rev-list --count main)
expect pass "unchanged manifest push" push
unchanged_ok() { [[ "$(git -C "$remote/keylatch/homebrew-tap.git" rev-list --count main)" == "$commits_before" ]]; }
expect pass "unchanged manifest adds no commit" unchanged_ok
expect fail "push without token" env -u PUSH_TOKEN PACKAGE_REPO_BASE="file://$remote" bash "$here/push-package-manifest.sh" keylatch/homebrew-tap keylatch.rb "$out/keylatch.rb" "$tag"

# coverage-threshold
cov="$work/cov"
mkdir -p "$cov"
m=github.com/keylatch/keylatch
cat >"$cov/profile.out" <<EOF
mode: atomic
$m/internal/sec/a.go:1.1,2.2 90 1
$m/internal/sec/a.go:3.1,4.2 10 0
$m/internal/sec/sub/b.go:1.1,2.2 80 1
$m/internal/sec/sub/b.go:3.1,4.2 20 0
$m/internal/other/c.go:1.1,2.2 70 1
$m/internal/other/c.go:3.1,4.2 30 0
$m/internal/other/c.go:3.1,4.2 30 2
$m/cmd/tool/main.go:1.1,2.2 10 0
EOF
floors() { printf '%s\n' "$@" >"$cov/floors.txt"; }
threshold() { bash "$here/coverage-threshold.sh" --floors "$cov/floors.txt" "$cov/profile.out"; }
floors "total 80" "default 80" "internal/sec/... 80" "cmd/tool exempt main package"
expect pass "floors met, duplicate blocks merged" threshold
floors "total 80" "default 80" "internal/sec/... 85" "cmd/tool exempt main package"
expect fail "subpackage below pattern floor" threshold
floors "total 80" "default 80" "internal/sec/... 85" "internal/sec/sub 80" "cmd/tool exempt main package"
expect pass "exact floor overrides pattern" threshold
floors "total 80" "default 80"
expect fail "unexempt package at zero" threshold
floors "total 90" "default 0"
expect fail "total below floor" threshold
floors "total 80" "default 80" "cmd/tool exempt"
expect fail "exemption without reason" threshold
floors "total 80" "default 80" "cmd/tool exempt main package" "internal/gone 80"
expect fail "stale floor entry" threshold
floors "default 80" "cmd/tool exempt main package"
expect fail "missing total floor" threshold
floors "total 80" "default 80" "internal/sec 120" "cmd/tool exempt main package"
expect fail "floor out of range" threshold
expect fail "missing profile" bash "$here/coverage-threshold.sh" --floors "$cov/floors.txt" "$cov/absent.out"
expect pass "checked-in floors file parses" bash -c "bash '$here/coverage-threshold.sh' --floors '$here/coverage-floors.txt' '$cov/profile.out' 2>&1 | grep -q 'matches no package'"

echo "release checks: $passed passed, $failed failed"
((failed == 0))
