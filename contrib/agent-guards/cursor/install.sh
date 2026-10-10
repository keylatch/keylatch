#!/usr/bin/env bash
# Installs the Keylatch guard into Cursor's hooks.json (beforeShellExecution and beforeReadFile hooks).
set -euo pipefail

GUARD_PATH="$HOME/.keylatch/hooks/block-keylatch-exfiltration.sh"
CONFIG="$HOME/.cursor/hooks.json"

mkdir -p "$(dirname "$GUARD_PATH")"
cp "$(dirname "$0")/../claude-code/block-keylatch-exfiltration.sh" "$GUARD_PATH"
chmod +x "$GUARD_PATH"
rm -f "$HOME/.keylatch/hooks/cursor-guard.sh" "$HOME/.keylatch/guards/cursor-guard.sh"

mkdir -p "$(dirname "$CONFIG")"

python3 - "$CONFIG" "\"$GUARD_PATH\" --harness cursor" <<'PYEOF'
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
data.setdefault("version", 1)
for event in ("beforeShellExecution", "beforeReadFile"):
    entries = data.setdefault("hooks", {}).setdefault(event, [])
    if not any(e.get("command") == command for e in entries):
        entries.append({"command": command, "timeout": 10, "failClosed": True})
path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

# Older versions registered the guard in settings.json, which Cursor does not
# read for hooks; drop that entry.
OLD_SETTINGS="$HOME/.cursor/settings.json"
if [ -f "$OLD_SETTINGS" ]; then
python3 - "$OLD_SETTINGS" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
command = ""
data = json.loads(path.read_text())
before = json.dumps(data)
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
if json.dumps(data) != before:
    path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF
fi

echo "Cursor guard installed."
echo "Guard script: $GUARD_PATH"
echo "Config: $CONFIG"
