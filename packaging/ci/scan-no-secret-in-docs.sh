#!/usr/bin/env bash
# scan-no-secret-in-docs.sh — S-INV-10 gate.
# Rejects any documentation or example file that contains a plaintext --field value
# for a sensitive field, or any real-looking API key (e.g. sk-* patterns).
#
# Usage: bash packaging/ci/scan-no-secret-in-docs.sh
# Exit 0 = clean. Exit 1 = insecure pattern found.
set -euo pipefail

FAIL=0

# Pattern 1: --field name=value where value is not @- or @prompt (looks like a real secret).
# Matches: --field api_key=sk-real-key  but not: --field api_key=@-
if grep -rEn -- '--field [a-zA-Z_]+=([^@$'"'"'"[:space:]])[^[:space:]]*' docs/ examples/ README.md 2>/dev/null; then
    echo "FAIL: insecure --field value found in docs/examples — use @- or @prompt"
    FAIL=1
fi

# Pattern 2: real-looking API keys (Anthropic/OpenAI style sk-* with 20+ chars).
if grep -rEn 'sk-[a-zA-Z0-9]{20,}' docs/ examples/ README.md 2>/dev/null; then
    echo "FAIL: real-looking API key found in docs/examples"
    FAIL=1
fi

if [[ $FAIL -eq 0 ]]; then
    echo "PASS: no insecure patterns found in docs/examples"
fi

exit "$FAIL"
