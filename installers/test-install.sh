#!/usr/bin/env bash
# Cross-platform install smoke test.
# Usage: test-install.sh <artifact-path> <expected-version>
# Example: test-install.sh dist/keylatch-v0.1.0-darwin-arm64.tar.gz v0.1.0
set -euo pipefail

artifact="${1:?artifact path required}"
expected_version="${2:?expected version required}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "==> Extracting $artifact to $tmpdir"
case "$artifact" in
  *.tar.gz) tar -xzf "$artifact" -C "$tmpdir" ;;
  *.zip)    unzip -q "$artifact" -d "$tmpdir" ;;
  *)        echo "Unknown archive format: $artifact" >&2; exit 1 ;;
esac

binary="$(find "$tmpdir" -name "keylatch" -o -name "keylatch.exe" | head -1)"
if [[ -z "$binary" ]]; then
  echo "No keylatch binary found in archive" >&2
  exit 1
fi
chmod +x "$binary"

echo "==> Testing --version"
version_output="$("$binary" --version 2>&1)"
if [[ "$version_output" != *"$expected_version"* ]]; then
  echo "Version mismatch: expected $expected_version, got: $version_output" >&2
  exit 1
fi
echo "  OK: $version_output"

echo "==> Testing --help (deterministic output)"
help_output="$("$binary" --help 2>&1)"
if [[ -z "$help_output" ]]; then
  echo "--help produced no output" >&2
  exit 1
fi
echo "  OK: --help returned $(echo "$help_output" | wc -l) lines"

echo "==> Testing doctor --json in isolated HOME"
tmp_home="$(mktemp -d)"
trap 'rm -rf "$tmpdir" "$tmp_home"' EXIT
doctor_output="$(HOME="$tmp_home" "$binary" doctor --json 2>&1)" || true
if ! echo "$doctor_output" | grep -q '"version"'; then
  echo "doctor --json did not return expected JSON shape" >&2
  echo "$doctor_output" >&2
  exit 1
fi
echo "  OK: doctor --json returned valid JSON"

echo "==> Install smoke test passed for $expected_version"
