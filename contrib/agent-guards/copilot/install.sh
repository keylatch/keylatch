#!/usr/bin/env bash
# Installs the Keylatch guard as a shell wrapper for GitHub Copilot CLI.
# Note: Installing shell wrapper (native Copilot CLI hook config path unconfirmed).
# Wrapper intercepts copilot invocations via shell function in RC files.
set -euo pipefail

GUARD_PATH="$HOME/.keylatch/guards/copilot-guard.sh"

# Copy guard script into place.
mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"

echo "Installing shell wrapper (native Copilot CLI hook config path unconfirmed)."
echo "Wrapper intercepts copilot invocations."
echo "For native hook support verify current docs at keylatch.dev/integrations/copilot"
echo ""

# Append a copilot wrapper function to shell RC files.
WRAPPER='
# Keylatch Copilot guard wrapper
_keylatch_copilot_guard() {
    if [ -x "$HOME/.keylatch/guards/copilot-guard.sh" ]; then
        COPILOT_TOOL_NAME="Bash" COPILOT_TOOL_INPUT="$*" "$HOME/.keylatch/guards/copilot-guard.sh" || return $?
    fi
}
'

for RC in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -f "$RC" ] && ! grep -q "keylatch_copilot_guard" "$RC"; then
        echo "$WRAPPER" >> "$RC"
        echo "Guard wrapper appended to $RC"
    fi
done

echo "Copilot guard installed."
echo "Guard script: $GUARD_PATH"
echo "Restart your shell or source your RC file to activate."
