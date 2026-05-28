#!/usr/bin/env bash
# Installs the Keylatch guard into Aider's config (~/.aider.conf.yml).
set -euo pipefail

CONF="$HOME/.aider.conf.yml"
GUARD_PATH="$HOME/.keylatch/guards/aider-guard.sh"

# Copy guard script into place.
mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"

if ! grep -q "pre-tool-use-hook" "$CONF" 2>/dev/null; then
    echo "pre-tool-use-hook: $GUARD_PATH" >> "$CONF"
    echo "Aider guard installed."
    echo "Guard script: $GUARD_PATH"
    echo "Config: $CONF"
else
    echo "Aider guard already installed (skipping)."
    echo "Guard script: $GUARD_PATH"
fi
