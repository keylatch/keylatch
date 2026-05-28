#!/usr/bin/env bash
# Installs the Keylatch guard into Cursor's settings.json (PreToolUse hook).
set -euo pipefail

SETTINGS="$HOME/.cursor/settings.json"
GUARD_PATH="$HOME/.keylatch/guards/cursor-guard.sh"

# Copy guard script into place.
mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"

mkdir -p "$(dirname "$SETTINGS")"

# Use python3 to merge JSON (available on macOS/Linux).
python3 - "$SETTINGS" "$GUARD_PATH" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
guard = sys.argv[2]

data = json.loads(path.read_text()) if path.exists() else {}
hooks = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
if not hooks:
    hooks.append({"matcher": "*", "hooks": []})

inner = hooks[0].setdefault("hooks", [])
existing_cmds = [h.get("command") for h in inner]
if guard not in existing_cmds:
    inner.append({"type": "command", "command": guard})

path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

echo "Cursor guard installed."
echo "Guard script: $GUARD_PATH"
echo "Settings: $SETTINGS"
