#!/usr/bin/env bash
# Lets bootstrap keep a throwaway vault key in a plaintext file on a CI runner,
# which has neither an OS keyring nor a terminal for a passphrase.
#
# Keylatch reads that permission from the operator's own config file only: the
# default config path under the account's home in the user database, never a
# flag or an environment variable. This script writes that file for the account
# running the job. Run it only on ephemeral CI runners.
set -euo pipefail

[[ "$(uname -s)" == "Linux" ]] || exit 0

operator_home="$(getent passwd "$(id -u)" | cut -d: -f6)"
dir="$operator_home/.config/keylatch"
file="$dir/config.json"

mkdir -p "$dir"
chmod 700 "$dir"
if [[ ! -e "$file" ]]; then
  printf '{"version": 1, "allow_insecure_file_kek": true}\n' >"$file"
  chmod 600 "$file"
fi
