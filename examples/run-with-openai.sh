#!/usr/bin/env bash
set -euo pipefail

# Register an OpenAI credential.
# Pass the API key via stdin to avoid shell history exposure.
#
#   With 1Password:
#     keylatch connect openai --provider-ref api_key=op://vault/openai/credential
#
#   With stdin (CI-safe):
printf '%s' "$OPENAI_API_KEY" | keylatch connect openai -f api_key=@-

# Run a script with the OpenAI credential injected into the environment.
# Keylatch resolves the connection and sets OPENAI_API_KEY for the subprocess.
keylatch run openai -- node script.js
