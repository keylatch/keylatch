#!/usr/bin/env bash
# Installs the Keylatch guard into Gemini CLI's settings.json (BeforeTool hook).
set -euo pipefail

GUARD_PATH="$HOME/.keylatch/guards/gemini-guard.sh"

# Copy guard script into place.
mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"

# Try both common config paths.
if [ -f "$HOME/.gemini/settings.json" ]; then
    SETTINGS="$HOME/.gemini/settings.json"
elif [ -f "$HOME/.config/gemini/settings.json" ]; then
    SETTINGS="$HOME/.config/gemini/settings.json"
else
    # Default to ~/.gemini/settings.json
    SETTINGS="$HOME/.gemini/settings.json"
    mkdir -p "$(dirname "$SETTINGS")"
fi

python3 - "$SETTINGS" "$GUARD_PATH" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
guard = sys.argv[2]

data = json.loads(path.read_text()) if path.exists() else {}
hooks = data.setdefault("hooks", {}).setdefault("BeforeTool", [])
if not hooks:
    hooks.append({"matcher": "*", "hooks": []})

inner = hooks[0].setdefault("hooks", [])
existing_cmds = [h.get("command") for h in inner]
if guard not in existing_cmds:
    inner.append({"type": "command", "command": guard})

path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

echo "Gemini guard installed."
echo "Guard script: $GUARD_PATH"
echo "Settings: $SETTINGS"
