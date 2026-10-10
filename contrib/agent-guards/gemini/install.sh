#!/usr/bin/env bash
# Installs the Keylatch guard into Gemini CLI's settings.json (BeforeTool hook).
set -euo pipefail

GUARD_PATH="$HOME/.keylatch/hooks/block-keylatch-exfiltration.sh"
if [ -f "$HOME/.gemini/settings.json" ] || [ ! -f "$HOME/.config/gemini/settings.json" ]; then
    CONFIG="$HOME/.gemini/settings.json"
else
    CONFIG="$HOME/.config/gemini/settings.json"
fi

mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/../claude-code/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"
rm -f "$HOME/.keylatch/hooks/gemini-guard.sh" "$HOME/.keylatch/guards/gemini-guard.sh"

mkdir -p "$(dirname "$CONFIG")"

python3 - "$CONFIG" "\"$GUARD_PATH\" --harness gemini" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
command = sys.argv[2]

data = json.loads(path.read_text()) if path.exists() else {}
import re

LEGACY = re.compile(r"\.keylatch[/\\](hooks|guards)[/\\][a-z-]+-guard\.sh")


def stale(cmd):
    return isinstance(cmd, str) and cmd != command and ("block-keylatch-exfiltration.sh" in cmd or LEGACY.search(cmd))


def prune(node):
    """Drop hook entries that run an older guard script, and containers that empty out."""
    if isinstance(node, list):
        out = []
        for item in node:
            if isinstance(item, dict) and (stale(item.get("command")) or stale(item.get("bash"))):
                continue
            had_hooks = isinstance(item, dict) and "hooks" in item
            item = prune(item)
            if had_hooks and not item.get("hooks"):
                continue
            out.append(item)
        return out
    if isinstance(node, dict):
        for key in list(node):
            node[key] = prune(node[key])
            if node[key] == [] or node[key] == {}:
                del node[key]
    return node
data = prune(data)
groups = data.setdefault("hooks", {}).setdefault("BeforeTool", [])
if not any(h.get("command") == command for g in groups for h in g.get("hooks", [])):
    groups.append({
        "matcher": "run_shell_command|read_file|read_many_files|glob|search_file_content|grep_search",
        "hooks": [{"type": "command", "name": "keylatch-guard", "command": command, "timeout": 10000}],
    })
path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

echo "Gemini guard installed."
echo "Guard script: $GUARD_PATH"
echo "Config: $CONFIG"
