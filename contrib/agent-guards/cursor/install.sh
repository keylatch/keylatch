#!/usr/bin/env bash
# Installs the Keylatch guard into Cursor's hooks.json (beforeShellExecution hook).
set -euo pipefail

GUARD_PATH="$HOME/.keylatch/hooks/block-keylatch-exfiltration.sh"
CONFIG="$HOME/.cursor/hooks.json"

mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/../claude-code/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"

mkdir -p "$(dirname "$CONFIG")"

python3 - "$CONFIG" "$GUARD_PATH --harness cursor" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
command = sys.argv[2]

data = json.loads(path.read_text()) if path.exists() else {}
data.setdefault("version", 1)
entries = data.setdefault("hooks", {}).setdefault("beforeShellExecution", [])
if not any(e.get("command") == command for e in entries):
    entries.append({"command": command, "timeout": 10, "failClosed": True})
path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

echo "Cursor guard installed."
echo "Guard script: $GUARD_PATH"
echo "Config: $CONFIG"
