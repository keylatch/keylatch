#!/usr/bin/env bash
# Installs the Keylatch guard into GitHub Copilot's user hooks directory (PreToolUse hook).
set -euo pipefail

GUARD_PATH="$HOME/.keylatch/hooks/block-keylatch-exfiltration.sh"
CONFIG="${COPILOT_HOME:-$HOME/.copilot}/hooks/keylatch-guard.json"

mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/../claude-code/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"

mkdir -p "$(dirname "$CONFIG")"

python3 - "$CONFIG" "$GUARD_PATH --harness copilot" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
command = sys.argv[2]

data = json.loads(path.read_text()) if path.exists() else {}
data.setdefault("version", 1)
entries = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
if not any(e.get("bash") == command for e in entries):
    entries.append({"type": "command", "bash": command, "timeoutSec": 10})
path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

echo "Copilot guard installed."
echo "Guard script: $GUARD_PATH"
echo "Config: $CONFIG"
