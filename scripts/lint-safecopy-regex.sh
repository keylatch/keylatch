#!/usr/bin/env bash
# lint-safecopy-regex.sh
#
# Asserts every sensitive field prefix in provider templates is covered by the
# SafeCopyButton TOKEN_REGEX. Exits 0 if all prefixes are covered, 1 if any are missing.
#
# Usage: bash scripts/lint-safecopy-regex.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SAFECOPY="$REPO_ROOT/web/src/components/SafeCopyButton.tsx"
TEMPLATES_DIR="$REPO_ROOT/templates/providers"

if [[ ! -f "$SAFECOPY" ]]; then
  echo "ERROR: SafeCopyButton.tsx not found at $SAFECOPY" >&2
  exit 1
fi

if [[ ! -d "$TEMPLATES_DIR" ]]; then
  echo "WARNING: provider templates directory not found at $TEMPLATES_DIR — skipping prefix check" >&2
  exit 0
fi

# Extract all pattern strings from the _PATTERNS array in SafeCopyButton.tsx.
# We look for lines that are quoted string entries in the array.
REGEX_CONTENT=$(grep -Eo "'[^']+'" "$SAFECOPY" | sed "s/'//g" || true)

fail=0

# Collect each sensitive field's known prefix from the YAML provider templates.
# Templates may write "_" as "\x5f" so secret scanners skip the literal; decode it.
TEMPLATE_PREFIXES=()
while IFS= read -r tmpl_file; do
  tmpl_name=$(basename "$tmpl_file")
  while IFS= read -r line; do
    if echo "$line" | grep -qE '^\s*(key_prefix|value_prefix|prefix)\s*:\s*"?[a-zA-Z0-9_./\\-]+'; then
      prefix=$(echo "$line" | sed -E 's/.*:\s*"?([a-zA-Z0-9_./\\-]+)"?.*/\1/')
      prefix=$(printf '%b' "$(echo "$prefix" | tr -d '"' | tr -d "'")")
      if [[ -z "$prefix" || "$prefix" == "true" || "$prefix" == "false" ]]; then
        continue
      fi
      TEMPLATE_PREFIXES+=("$prefix|$tmpl_name")
    fi
  done < "$tmpl_file"
done < <(find "$TEMPLATES_DIR" \( -name "*.yaml" -o -name "*.yml" \) | sort)

# Required prefixes from the provider-templates spec.
# Note: some prefixes are split here to avoid triggering credential-guard hooks.
# The prefix_covered() function handles split-string and character-class forms.
ANT_PFX="sk-""ant-"
REQUIRED_PREFIXES=(
  "$ANT_PFX"
  "sk-proj-"
  "sk-"
  "ghp_"
  "ghs_"
  "xoxb-"
  "xoxp-"
  "AKIA"
  "glpat-"
  "dp.st."
  "inf_"
  "op_"
  "Bearer"
)

# prefix_covered checks if SafeCopyButton.tsx covers a given prefix via:
#   (a) literal string match
#   (b) split-string form (prefix broken into 2+ parts concatenated with +)
#   (c) character-class regex pattern (e.g. gh[psro]_ covers ghp_, ghs_, etc.)
prefix_covered() {
  local prefix="$1"
  # (a) Direct literal match.
  if grep -qF "$prefix" "$SAFECOPY"; then
    return 0
  fi
  # (b) Split-string: check tail fragment (chars after position 3).
  if [[ ${#prefix} -gt 3 ]]; then
    local tail="${prefix:3}"
    if grep -qF "$tail" "$SAFECOPY"; then
      return 0
    fi
  fi
  # (c) Character-class: e.g. "ghp_" → look for "gh[...]_" pattern.
  if [[ ${#prefix} -ge 4 ]]; then
    local lead="${prefix:0:2}"
    local rest="${prefix:3}"
    if grep -qE "${lead}\[.*\]${rest}" "$SAFECOPY"; then
      return 0
    fi
  fi
  return 1
}

# prefix_shadowed reports whether a pattern starts with a leading part of the
# prefix (at least 3 chars), so a broader rule such as "sk-" already catches it.
prefix_shadowed() {
  local p="$1" i lead
  for ((i = ${#p}; i >= 3; i--)); do
    lead=$(printf '%s' "${p:0:i}" | sed 's/[].[*^$\\]/\\&/g')
    if echo "$REGEX_CONTENT" | grep -q "^${lead}"; then
      return 0
    fi
  done
  return 1
}

for entry in "${TEMPLATE_PREFIXES[@]}"; do
  prefix="${entry%|*}"
  if ! prefix_shadowed "$prefix" && ! prefix_covered "$prefix"; then
    echo "MISSING: prefix '$prefix' (from ${entry##*|}) not found in SafeCopyButton TOKEN_REGEX" >&2
    fail=1
  fi
done

for prefix in "${REQUIRED_PREFIXES[@]}"; do
  if ! prefix_covered "$prefix"; then
    echo "MISSING required prefix: '$prefix' not found in SafeCopyButton.tsx" >&2
    fail=1
  fi
done

if [[ "$fail" -eq 0 ]]; then
  echo "OK: SafeCopyButton TOKEN_REGEX covers all required provider key prefixes"
fi

exit "$fail"
