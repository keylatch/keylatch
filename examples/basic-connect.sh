#!/usr/bin/env bash
set -euo pipefail

# Bootstrap keylatch configuration (creates ~/.keylatch/config.json)
keylatch bootstrap

# Register a credential for the openrouter provider.
# Use --provider-ref to pull the key from an external store (recommended),
# or pass via stdin to avoid shell history exposure.
#
#   With 1Password:
#     keylatch connect openrouter --provider-ref api_key=op://vault/openrouter/credential
#
#   With stdin (CI-safe):
printf '%s' "$OPENROUTER_API_KEY" | keylatch connect openrouter -f api_key=@-
