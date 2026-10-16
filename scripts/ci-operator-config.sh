#!/usr/bin/env bash
# Lets bootstrap keep a throwaway vault key in a plaintext file on a CI runner
# that has neither a usable OS keyring nor a terminal for a passphrase.
#
# Keylatch reads that permission from the operator's own config file only: the
# default config path under the account's home in the user database, never a
# flag or an environment variable. This script writes that file for the account
# running the job. Run it only on ephemeral CI runners.
#
# The file is a complete config, not just the permission: when a job points
# XDG_CONFIG_HOME or HOME at the operator's directories, keylatch reads this
# same file as its own config and needs a backend in it.
set -euo pipefail

case "$(uname -s)" in
  Linux)
    operator_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
    file="$operator_home/.config/keylatch/config.json"
    ;;
  Darwin)
    operator_home="$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory | awk '{print $2}')"
    file="$operator_home/.keylatch/config.json"
    ;;
  *)
    exit 0
    ;;
esac

dir="$(dirname "$file")"
mkdir -p "$dir"
chmod 700 "$dir"
if [[ ! -e "$file" ]]; then
  printf '{"version": 1, "backend": "file", "allow_insecure_file_kek": true}\n' >"$file"
  chmod 600 "$file"
fi
