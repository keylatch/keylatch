#!/usr/bin/env bash
# keylatch-hook-version: 1
# Gemini CLI BeforeTool guard. stdout MUST be JSON only.
# Returns {"decision":"deny","reason":"..."} to block, {"decision":"allow"} to pass.
set -euo pipefail

event=$(cat)
cmd=$(echo "$event" | python3 -c "
import sys, json
e = json.load(sys.stdin)
ti = e.get('tool_input', {})
print(ti.get('command', '') or ti.get('cmd', '') or e.get('tool_name', ''))
" 2>/dev/null || echo "")

deny() {
    printf '{"decision":"deny","reason":"Keylatch guard: credential access blocked. Use keylatch run instead."}\n'
    exit 0
}

allow() {
    printf '{"decision":"allow"}\n'
    exit 0
}

echo "$cmd" | grep -qE 'keylatch (get|secret get)' && deny
echo "$cmd" | grep -qE 'security find-(password|generic-password)' && deny
echo "$cmd" | grep -qE '(op read|bw get)' && deny
echo "$cmd" | grep -qE '\.keylatch/keylatch\.keychain-db' && deny
echo "$cmd" | grep -qE 'cat .*\.keylatch/config\.yaml' && deny
allow
