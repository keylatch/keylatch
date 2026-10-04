#!/usr/bin/env bash
# Renders the Homebrew formula and Scoop manifest for a release from its
# checksums file.
# Usage: render-package-manifests.sh <tag> <checksums-file> <out-dir>
# Writes <out-dir>/keylatch.rb and <out-dir>/keylatch.json.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

tag="${1:?usage: render-package-manifests.sh <tag> <checksums-file> <out-dir>}"
sums="${2:?usage: render-package-manifests.sh <tag> <checksums-file> <out-dir>}"
out="${3:?usage: render-package-manifests.sh <tag> <checksums-file> <out-dir>}"
require_tag "$tag"
[[ -f "$sums" ]] || die "checksums file not found: $sums"
version="${tag#v}"
base_url="https://github.com/keylatch/keylatch/releases/download/${tag}"
description="Zero-trust credential vault CLI for AI-assisted workflows"

sha_for() {
  local name="$1" sha
  sha=$(awk -v n="$name" '$2 == n { print $1 }' "$sums")
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "$sums has no sha256 for $name"
  echo "$sha"
}

declare -A formula_url formula_sha
for platform in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
  archive="keylatch_${version}_${platform}.tar.gz"
  formula_url[$platform]="${base_url}/${archive}"
  formula_sha[$platform]=$(sha_for "$archive")
done
windows_archive="keylatch_${version}_windows_amd64.zip"
windows_sha=$(sha_for "$windows_archive")

mkdir -p "$out"
cat >"$out/keylatch.rb" <<EOF
# typed: false
# frozen_string_literal: true

class Keylatch < Formula
  desc "${description}"
  homepage "https://github.com/keylatch/keylatch"
  version "${version}"
  license "Apache-2.0"

  on_macos do
    if Hardware::CPU.intel?
      url "${formula_url[darwin_amd64]}"
      sha256 "${formula_sha[darwin_amd64]}"
    end
    if Hardware::CPU.arm?
      url "${formula_url[darwin_arm64]}"
      sha256 "${formula_sha[darwin_arm64]}"
    end
  end

  on_linux do
    if Hardware::CPU.intel? && Hardware::CPU.is_64_bit?
      url "${formula_url[linux_amd64]}"
      sha256 "${formula_sha[linux_amd64]}"
    end
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "${formula_url[linux_arm64]}"
      sha256 "${formula_sha[linux_arm64]}"
    end
  end

  def install
    bin.install "keylatch"
    generate_completions_from_executable(bin/"keylatch", "completion")
  end

  test do
    system "#{bin}/keylatch", "--version"
  end
end
EOF

jq -n \
  --arg version "$version" \
  --arg url "${base_url}/${windows_archive}" \
  --arg hash "$windows_sha" \
  --arg description "$description" \
  '{
    version: $version,
    architecture: {"64bit": {url: $url, bin: ["keylatchd.exe", "keylatch.exe"], hash: $hash}},
    homepage: "https://github.com/keylatch/keylatch",
    license: "Apache-2.0",
    description: $description
  }' >"$out/keylatch.json"

echo "rendered Homebrew formula and Scoop manifest for $tag in $out"
