#!/usr/bin/env bash
# Installs the Keylatch guard for one harness into a scratch home and checks
# that the published harness still accepts what was written.
#
# Usage: harness-drift.sh <keylatch binary> <harness id> <harness executable> <list command>
#
# The list command is the harness's own command that reads its MCP
# configuration (for example "claude mcp list"); it parses the file the
# installer wrote, so a format change makes it fail or stop listing keylatch.
# With KEYLATCH_DRIFT_BREAK=1 the written hook file is damaged first, which
# `keylatch doctor --agents` must report; the script then fails on purpose.
set -euo pipefail

keylatch="${1:?keylatch binary}"
harness="${2:?harness id}"
exe="${3:?harness executable}"
list_cmd="${4:?list command}"

drift_home="$(mktemp -d)"
version=unavailable
finish() {
  status=$?
  if [ -n "${KEYLATCH_DRIFT_RESULT:-}" ]; then
    result=fail
    if [ "$status" = 0 ]; then result=pass; fi
    jq -n --arg harness "$harness" --arg version "$version" --arg result "$result" \
      --arg checked_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg commit "${GITHUB_SHA:-}" \
      --arg run_url "${KEYLATCH_DRIFT_RUN_URL:-}" \
      '{harness:$harness,version:$version,result:$result,checked_at:$checked_at,commit:$commit,run_url:$run_url,scope:"published-cli-config-reader"}' \
      >"$KEYLATCH_DRIFT_RESULT" || status=1
  fi
  rm -rf "$drift_home"
  exit "$status"
}
trap finish EXIT
export HOME="$drift_home" USERPROFILE="$drift_home"
unset CLAUDE_CONFIG_DIR CODEX_HOME COPILOT_HOME GEMINI_CLI_HOME XDG_CONFIG_HOME

command -v "$exe" >/dev/null || { echo "::error::$exe is not installed"; exit 1; }
version="$(timeout 20s "$exe" --version 2>&1 | head -c 1024 | head -n 1)"
echo "== $exe $version"

echo "== agent install --dry-run"
"$keylatch" agent install "$harness" --dry-run

echo "== agent install"
"$keylatch" agent install "$harness"

if [ "${KEYLATCH_DRIFT_BREAK:-}" = 1 ]; then
  echo "== damaging the hook file on purpose"
  hook_file="$("$keylatch" doctor --agents --json | jq -r --arg id "$harness" '.agents[] | select(.id == $id) | .hook_path')"
  [ -n "$hook_file" ] && [ "$hook_file" != null ] || { echo "::error::no hook file to damage"; exit 1; }
  printf '{' >"$hook_file"
fi

echo "== keylatch doctor --agents"
"$keylatch" doctor --agents

echo "== $list_cmd"
output="$(timeout 60s $list_cmd 2>&1)" || { echo "$output"; echo "::error::$list_cmd failed after the install"; exit 1; }
echo "$output"
echo "$output" | grep -qi keylatch || { echo "::error::$exe does not list the Keylatch MCP server"; exit 1; }
