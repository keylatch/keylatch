#!/usr/bin/env bash
set -euo pipefail

# Register AWS credentials.
# Pass credentials via stdin or --provider-ref to avoid shell history exposure.
#
#   With stdin (CI-safe):
printf '%s' "$AWS_ACCESS_KEY_ID" | keylatch connect aws -f access_key_id=@-
printf '%s' "$AWS_SECRET_ACCESS_KEY" | keylatch connect aws -f secret_access_key=@-

# Run a script with AWS credentials injected into the environment.
# Keylatch sets AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for the subprocess.
keylatch run aws -- python deploy.py
