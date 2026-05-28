#!/usr/bin/env bash
# keylatch-hook-version: 1
# Codex CLI PreToolUse guard — blocks credential-exfiltrating tool calls.
# Reads JSON event from stdin; outputs JSON decision to stdout.
set -euo pipefail

event=$(cat)
tool=$(echo "$event" | python3 -c "import sys,json; e=json.load(sys.stdin); print(e.get('tool_name',''))" 2>/dev/null || echo "")
args=$(echo "$event" | python3 -c "import sys,json; e=json.load(sys.stdin); print(json.dumps(e.get('tool_input',{})))" 2>/dev/null || echo "{}")
cmd=$(echo "$args" | python3 -c "import sys,json; e=json.load(sys.stdin); print(e.get('command','') or e.get('cmd',''))" 2>/dev/null || echo "")
check="$tool $cmd"

block() {
    echo '{"decision":"block","reason":"Keylatch guard: credential access blocked. Use keylatch run instead."}'
    exit 0
}

echo "$check" | grep -qE 'keylatch (get|secret get)' && block
echo "$check" | grep -qE 'security find-(password|generic-password)' && block
echo "$check" | grep -qE '(op read|bw get)' && block
echo "$check" | grep -qE '\.keylatch/keylatch\.keychain-db' && block
echo "$check" | grep -qE 'cat .*\.keylatch/config\.yaml' && block
exit 0
