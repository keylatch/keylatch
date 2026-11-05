#!/usr/bin/env bash
# Give one agent a short-lived token scoped to a single provider capability.
# The agent receives the token and the gateway URL, never the provider key.
set -euo pipefail

keylatch gateway init
keylatch gateway up --detach

# One capability, one hour, at most 50 calls.
keylatch gateway token create claude-code --allow openrouter.chat --ttl 1h --max-uses 50

keylatch gateway token list
keylatch gateway status
