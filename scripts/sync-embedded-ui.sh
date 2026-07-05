#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT/web"

bun install --frozen-lockfile
bun run build

cd "$ROOT"
rm -rf internal/ui/web/dist
mkdir -p internal/ui/web
cp -R web/dist internal/ui/web/dist

bash web/scripts/verify-bundle.sh
