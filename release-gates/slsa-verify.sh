#!/usr/bin/env bash
# SLSA provenance verification (placeholder — Phase 7 wires the pipeline; Phase 11 adds FIPS provenance).
# Usage: slsa-verify.sh <version> [provenance-file]
# Requires: slsa-verifier (https://github.com/slsa-framework/slsa-verifier)
set -euo pipefail

version="${1:?version required (e.g. v0.1.0)}"
provenance_file="${2:-dist/keylatch-${version}-provenance.intoto.jsonl}"

if [[ ! -f "$provenance_file" ]]; then
  echo "Provenance file not found: $provenance_file" >&2
  echo "Download from: https://github.com/keylatch/keylatch/releases/download/${version}/keylatch-${version}-provenance.intoto.jsonl" >&2
  exit 1
fi

if ! command -v slsa-verifier &>/dev/null; then
  echo "slsa-verifier not found — install from https://github.com/slsa-framework/slsa-verifier" >&2
  exit 1
fi

echo "==> Verifying SLSA provenance for $version"
slsa-verifier verify-artifact \
  --provenance-path "$provenance_file" \
  --source-uri "github.com/keylatch/keylatch" \
  --source-tag "$version"

echo "==> SLSA provenance verified for $version"
