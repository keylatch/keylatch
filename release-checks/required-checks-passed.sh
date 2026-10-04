#!/usr/bin/env bash
# Fails unless the most recent completed run of every required check on a
# commit concluded "success".
# Usage: required-checks-passed.sh <commit-sha>
# Env:   REQUIRED_CHECKS  space-separated check names (default: the checks
#                         required by main's branch protection)
#        GITHUB_REPOSITORY owner/repo (default keylatch/keylatch)
#        CHECK_RUNS_DIR    read <name>.json fixtures instead of calling the API
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

sha="${1:?usage: required-checks-passed.sh <commit-sha>}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || die "expected a full commit sha, got: $sha"
repo="${GITHUB_REPOSITORY:-keylatch/keylatch}"
read -r -a checks <<<"${REQUIRED_CHECKS:-gitleaks canary-regression sidecar-canary docs-leak-scan govulncheck}"

check_runs() {
  if [[ -n "${CHECK_RUNS_DIR:-}" ]]; then
    cat "${CHECK_RUNS_DIR}/$1.json"
  else
    gh api --paginate "repos/${repo}/commits/${sha}/check-runs?check_name=$1&per_page=100" \
      --jq '.check_runs[]' | jq -s '{check_runs: .}'
  fi
}

failed=0
for name in "${checks[@]}"; do
  conclusion=$(check_runs "$name" | jq -r '
    [.check_runs[] | select(.status == "completed")]
    | sort_by(.completed_at) | last | .conclusion // "missing"')
  if [[ "$conclusion" == "success" ]]; then
    echo "ok      $name"
  else
    echo "FAILED  $name ($conclusion)"
    failed=1
  fi
done

((failed == 0)) || die "required checks have not passed on $sha"
