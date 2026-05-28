#!/usr/bin/env bash
# Phase-0 CI gate — SC0-11
# Runs all checks required for a clean Phase-0 build.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> go test ./... -count=1 -race"
go test ./... -count=1 -race

echo "==> go vet ./..."
go vet ./...

echo "==> gofmt -l ."
UNFORMATTED="$(gofmt -l .)"
if [ -n "$UNFORMATTED" ]; then
	echo "gofmt found unformatted files:"
	echo "$UNFORMATTED"
	exit 1
fi

echo "==> hook test harness"
bash contrib/agent-guards/claude-code/block-keylatch-exfiltration.test.sh

echo ""
echo "All Phase-0 checks passed."
