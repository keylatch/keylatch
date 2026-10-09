#!/usr/bin/env bash
# Installs the Keylatch guard into Codex CLI's hooks config (~/.codex/hooks.json).
set -euo pipefail

GUARD_PATH="$HOME/.keylatch/hooks/block-keylatch-exfiltration.sh"
CONFIG="$HOME/.codex/hooks.json"

mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/../claude-code/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"

mkdir -p "$(dirname "$CONFIG")"

python3 - "$CONFIG" "$GUARD_PATH --harness codex" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
command = sys.argv[2]

data = json.loads(path.read_text()) if path.exists() else {}
groups = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
if not any(h.get("command") == command for g in groups for h in g.get("hooks", [])):
    groups.append({"matcher": "Bash", "hooks": [{"type": "command", "command": command, "timeout": 30}]})
path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

echo "Codex guard installed."
echo "Guard script: $GUARD_PATH"
echo "Config: $CONFIG"
echo "Review and trust the hook with /hooks in Codex before it runs."
