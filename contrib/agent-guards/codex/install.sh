#!/usr/bin/env bash
# Installs the Keylatch guard into Codex CLI's hooks config (~/.codex/hooks.json).
set -euo pipefail

HOOKS="$HOME/.codex/hooks.json"
GUARD_PATH="$HOME/.keylatch/guards/codex-guard.sh"

# Copy guard script into place.
mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"

mkdir -p "$(dirname "$HOOKS")"

python3 - "$HOOKS" "$GUARD_PATH" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
guard = sys.argv[2]

data = json.loads(path.read_text()) if path.exists() else {}
hooks = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
if not hooks:
    hooks.append({"matcher": ".*", "hooks": []})

inner = hooks[0].setdefault("hooks", [])
existing_cmds = [h.get("command") for h in inner]
if guard not in existing_cmds:
    inner.append({"type": "command", "command": guard, "timeout": 5000})

path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

echo "Codex guard installed."
echo "Guard script: $GUARD_PATH"
echo "Hooks config: $HOOKS"
