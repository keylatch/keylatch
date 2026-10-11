#!/usr/bin/env bash
# Installs the Keylatch guard into Codex CLI's hooks config (~/.codex/hooks.json).
set -euo pipefail

GUARD_PATH="$HOME/.keylatch/hooks/block-keylatch-exfiltration.sh"
CONFIG="$HOME/.codex/hooks.json"

mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/../claude-code/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"
rm -f "$HOME/.keylatch/hooks/codex-guard.sh" "$HOME/.keylatch/guards/codex-guard.sh"

mkdir -p "$(dirname "$CONFIG")"

python3 - "$CONFIG" "\"$GUARD_PATH\" --harness codex" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
command = sys.argv[2]

data = json.loads(path.read_text()) if path.exists() else {}
import re

LEGACY = re.compile(r"\.keylatch[/\\](hooks|guards)[/\\][a-z-]+-guard\.sh")


def stale(cmd):
    return isinstance(cmd, str) and cmd != command and ("block-keylatch-exfiltration.sh" in cmd or LEGACY.search(cmd))


def prune(node):
    """Drop hook entries that run an older guard script, and only the containers that removal emptied. Returns (node, changed)."""
    changed = False
    if isinstance(node, list):
        out = []
        for item in node:
            if isinstance(item, dict) and (stale(item.get("command")) or stale(item.get("bash"))):
                changed = True
                continue
            had_hooks = isinstance(item, dict) and "hooks" in item
            item, item_changed = prune(item)
            if item_changed:
                changed = True
                if had_hooks and "hooks" not in item:
                    continue
            out.append(item)
        return out, changed
    if isinstance(node, dict):
        for key in list(node):
            node[key], key_changed = prune(node[key])
            if key_changed:
                changed = True
                if node[key] == [] or node[key] == {}:
                    del node[key]
        return node, changed
    return node, False

data, _ = prune(data)
groups = data.setdefault("hooks", {}).setdefault("PreToolUse", [])
if not any(h.get("command") == command for g in groups for h in g.get("hooks", [])):
    groups.append({"matcher": "Bash", "hooks": [{"type": "command", "command": command, "timeout": 30}]})
path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

echo "Codex guard installed."
echo "Guard script: $GUARD_PATH"
echo "Config: $CONFIG"
echo "Review and trust the hook with /hooks in Codex before it runs."
