#!/usr/bin/env bash
# Installs the Keylatch guard plugin for OpenCode.
set -euo pipefail

PLUGIN_DIR="$HOME/.config/opencode/plugins/keylatch-guard"
OPENCODE_JSON="$HOME/.config/opencode/opencode.json"

# Copy plugin file.
mkdir -p "$PLUGIN_DIR"
cp "$(dirname "$0")/keylatch-guard.ts" "$PLUGIN_DIR/index.ts"

# Patch opencode.json to register the plugin.
python3 - "$OPENCODE_JSON" "$PLUGIN_DIR/index.ts" <<'PYEOF'
import sys, json, pathlib

path = pathlib.Path(sys.argv[1])
plugin_path = sys.argv[2]

data = json.loads(path.read_text()) if path.exists() else {}
plugins = data.setdefault("plugins", [])
if plugin_path not in plugins:
    plugins.append(plugin_path)

path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(data, indent=2) + "\n")
PYEOF

echo "OpenCode guard installed."
echo "Plugin: $PLUGIN_DIR/index.ts"
echo "Config: $OPENCODE_JSON"
