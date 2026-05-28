#!/usr/bin/env bash
# lint-callmeta-fields.sh — T-13-06
#
# Asserts that every JSON key in the callMeta struct in cmd_call.go is
# covered by the callMetaAllowedFields map in the same file.
# Exits 0 if all fields are covered, 1 if any are missing.
#
# Usage: bash scripts/lint-callmeta-fields.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMD_CALL="$REPO_ROOT/internal/cli/cmd_call.go"

if [[ ! -f "$CMD_CALL" ]]; then
  echo "ERROR: cmd_call.go not found at $CMD_CALL" >&2
  exit 1
fi

# Extract JSON tag names from the callMeta struct fields.
# We look for lines between "type callMeta struct {" and its closing "}"
# and extract the json tag value (the key before any comma or closing quote).
IN_STRUCT=0
declare -a STRUCT_FIELDS=()
while IFS= read -r line; do
  if echo "$line" | grep -qE '^\s*type\s+callMeta\s+struct\s*\{'; then
    IN_STRUCT=1
    continue
  fi
  if [[ "$IN_STRUCT" -eq 1 ]]; then
    if echo "$line" | grep -qE '^\s*\}'; then
      IN_STRUCT=0
      continue
    fi
    # Extract json tag: `json:"<key>,omitempty"` or `json:"<key>"`
    json_key=$(echo "$line" | sed -nE 's/.*`json:"([^",]+)[",].*/\1/p')
    if [[ -z "$json_key" ]]; then
      json_key=$(echo "$line" | sed -nE 's/.*`json:"([^"]+)".*/\1/p')
    fi
    if [[ -n "$json_key" && "$json_key" != "-" ]]; then
      STRUCT_FIELDS+=("$json_key")
    fi
  fi
done < "$CMD_CALL"

if [[ "${#STRUCT_FIELDS[@]}" -eq 0 ]]; then
  echo "WARNING: no fields found in callMeta struct — check the parser" >&2
  exit 0
fi

fail=0
for field in "${STRUCT_FIELDS[@]}"; do
  # Check that this field key appears in callMetaAllowedFields map.
  if ! grep -qF "\"$field\"" "$CMD_CALL"; then
    echo "MISSING: callMeta field '$field' not found in callMetaAllowedFields in $CMD_CALL" >&2
    fail=1
  fi
done

# Also check that every key in callMetaAllowedFields corresponds to a real struct field.
# Extract allowlist keys (lines like: "<key>": true)
while IFS= read -r line; do
  allowlist_key=$(echo "$line" | sed -nE 's/\s*"([^"]+)"\s*:\s*true.*/\1/p')
  if [[ -z "$allowlist_key" ]]; then
    continue
  fi
  found=0
  for sf in "${STRUCT_FIELDS[@]}"; do
    if [[ "$sf" == "$allowlist_key" ]]; then
      found=1
      break
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    echo "STALE: callMetaAllowedFields key '$allowlist_key' has no corresponding callMeta struct field" >&2
    fail=1
  fi
done < <(awk '/callMetaAllowedFields/,/^}/' "$CMD_CALL" || true)

if [[ "$fail" -eq 0 ]]; then
  echo "OK: all callMeta struct fields are covered by callMetaAllowedFields"
fi

exit "$fail"
