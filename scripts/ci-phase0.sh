#!/usr/bin/env bash
# CI gate — runs all checks required for a clean build.
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
echo "All checks passed."
