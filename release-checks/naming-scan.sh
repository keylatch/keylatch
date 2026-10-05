#!/usr/bin/env bash
# Fails when internal work-step labels (milestone, phase, round, stage, wave,
# plan or work-package numbers) or audit finding ids appear in tracked file
# names, file contents or, with --range, commit subjects.
#
# usage: naming-scan.sh [--range <rev-range>] [--docs]
#        naming-scan.sh --self-test
#
# --docs scans README.md, SECURITY.md and docs/ instead of the code tree.
set -euo pipefail

# One extended regex per label family; GNU grep -E syntax.
LABEL_PATTERNS=(
  '\b([Mm]ilestone|[Pp]hase|[Rr]ound|[Ss]tage|[Ww]ave|[Pp]lan|[Ww]ork[ -]?[Pp]ackage)[ _-]?[0-9]+[a-z]?\b'
  '([Mm]ilestone|MILESTONE|[Pp]hase|PHASE|[Rr]ound|ROUND|[Ss]tage|STAGE|[Ww]ave|WAVE)_?[0-9]+([A-Z_]|$)'
  '\b(wp|WP)[0-9]{1,3}\b'
  '(\b|[a-z_])M[0-9]{1,2}[a-z]?\b'
  '\b[SAHDQCLMN]-[0-9]{1,2}[a-z]?\b'
  '\bF[0-9]{2}\b'
  '_([FMHCLS][0-9]{1,2}|S[0-9]{1,2}_[0-9]{1,2})_'
  '\b(EPIC|FIND)[0-9]*-[0-9]+'
  '\b([Ee]pic|find)[0-9]+'
  '\(([HCLMF][0-9]{1,2}[a-z]?)([,/ ]+[HCLMF]?[0-9]{1,2}[a-z]?)*\)'
  '\b[Ff]inding[- ][0-9]+'
)

# Paths whose job is to record history verbatim, or to define the patterns.
EXCLUDED_PATHS=(
  ':!CHANGELOG.md'
  ':!docs/release-notes/'
  ':!release-checks/naming-scan.sh'
  ':!go.sum'
  ':!*.lock'
  ':!*package-lock.json'
  ':!*.svg'
  ':!src-tauri/gen/'
)

DOC_PATHS=(README.md SECURITY.md docs/)

# Docs that still carry labels; each is rewritten by the docs accuracy work
# and must be removed from this list when it is.
DOC_EXCEPTIONS=(
  docs/architecture/audit-log.md
  docs/architecture/broker.md
  docs/architecture/decisions/ADR-001-cosign-keyless-templates.md
  docs/architecture/decisions/ADR-002-experimental-env-unified.md
  docs/architecture/registry-signing.md
  docs/backends/external-references.md
  docs/backends/file.md
  docs/backends/index.md
  docs/cli/environment.md
  docs/cli-reference.md
  docs/desktop-parity.md
  docs/experimental.md
  docs/man/keylatch-proxy.1
  docs/runtime-modes.md
  docs/sandbox.md
  docs/security.md
  SECURITY.md
)

# Tokens that match a pattern but are not labels: chip names, SVG path data.
ALLOWED_TOKENS='Apple M[0-9]|\bM[0-9]{1,2} (chip|Mac|Max|Pro)\b|\bd="[Mm][0-9]'

combined_pattern() {
  local IFS='|'
  printf '(%s)' "${LABEL_PATTERNS[*]}"
}

scan_names() {
  local pattern
  pattern=$(combined_pattern)
  # Underscores, dots and slashes separate words in file and directory names.
  paste -d '\t' <(git ls-files -- "$@") <(git ls-files -- "$@" | sed 's|[_./]| |g') |
    grep -E -- $'\t'".*$pattern" | cut -f1 || true
}

scan_contents() {
  local pattern
  pattern=$(combined_pattern)
  git grep -I -n -E -- "$pattern" -- "$@" | grep -Ev -- "$ALLOWED_TOKENS" || true
}

scan_subjects() {
  local pattern
  pattern=$(combined_pattern)
  git log --format='%h %s' "$1" | grep -E -- "$pattern" | grep -Ev -- "$ALLOWED_TOKENS" || true
}

run_scan() {
  local range="" docs=0
  while (($#)); do
    case "$1" in
      --range) range="${2:?--range needs a revision range}"; shift 2 ;;
      --docs) docs=1; shift ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
  done

  local -a paths=()
  if ((docs)); then
    paths=("${DOC_PATHS[@]}" ':!docs/release-notes/')
    local d
    for d in "${DOC_EXCEPTIONS[@]}"; do paths+=(":!$d"); done
  else
    paths=(. "${EXCLUDED_PATHS[@]}")
    local d
    for d in "${DOC_PATHS[@]}"; do paths+=(":!$d"); done
  fi

  local names contents subjects=""
  names=$(scan_names "${paths[@]}")
  contents=$(scan_contents "${paths[@]}")
  [[ -n "$range" ]] && subjects=$(scan_subjects "$range")

  local failed=0
  if [[ -n "$names" ]]; then
    echo "Labelled file or directory names:"
    printf '%s\n' "$names" | sed 's/^/  /'
    failed=1
  fi
  if [[ -n "$contents" ]]; then
    echo "Labels in file contents:"
    printf '%s\n' "$contents" | sed 's/^/  /'
    failed=1
  fi
  if [[ -n "$subjects" ]]; then
    echo "Labels in commit subjects ($range):"
    printf '%s\n' "$subjects" | sed 's/^/  /'
    failed=1
  fi
  if ((failed)); then
    echo "naming-scan: describe what the code does instead of the work item behind it." >&2
    return 1
  fi
  echo "naming-scan: clean"
}

self_test() {
  local script work status passed=0 failed=0
  script="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  work=$(mktemp -d)
  trap 'rm -rf "$work"' RETURN

  fixture() {
    rm -rf "$work/repo"
    git init -q -b main "$work/repo"
    mkdir -p "$work/repo/internal/pkg" "$work/repo/docs"
    printf 'package pkg\n\n// Run starts the server.\nfunc Run() {}\n' >"$work/repo/internal/pkg/run.go"
    printf '# Guide\n\nRuns on Apple M1 and M2 Mac hardware.\n' >"$work/repo/docs/guide.md"
    git -C "$work/repo" add -A
    git -C "$work/repo" -c user.name=t -c user.email=t@example.com commit -q -m "feat(pkg): add server"
  }
  commit_all() {
    git -C "$work/repo" add -A
    git -C "$work/repo" -c user.name=t -c user.email=t@example.com commit -q -m "$1"
  }
  expect() {
    local want="$1" name="$2"
    shift 2
    status=0
    (cd "$work/repo" && bash "$script" "$@") >"$work/out.log" 2>&1 || status=$?
    if { [[ "$want" == pass ]] && ((status == 0)); } || { [[ "$want" == fail ]] && ((status != 0)); }; then
      passed=$((passed + 1))
    else
      failed=$((failed + 1))
      echo "FAIL: $name (exit $status)"
      sed 's/^/    /' "$work/out.log"
    fi
  }

  fixture
  expect pass "clean tree"
  expect pass "clean docs" --docs
  expect pass "clean subjects" --range HEAD

  local label
  for label in phase2_helper.go round3_test.go wp01_scope.go epic12_test.go find3_test.go; do
    fixture
    printf 'package pkg\n' >"$work/repo/internal/pkg/$label"
    commit_all "test: add file"
    expect fail "file name $label"
  done

  for label in 'manifest.M1()' 'UnselectableInM1' 'TestSecurityRegression_F36_Traversal' 'Phase4Sentinel' 'KEYLATCH_CANARY_PHASE3_X' 'see F34' 'fixes S-01' '(H7)' '(F27, F28)' 'Finding-001' 'EPIC-08' 'FIND2-007' 'stage 2 rollout' 'Phase4 stub'; do
    fixture
    printf 'package pkg\n\n// %s\nfunc Gate() {}\n' "$label" >"$work/repo/internal/pkg/gate.go"
    commit_all "feat(pkg): add gate"
    expect fail "content $label"
  done

  fixture
  printf '# Guide\n\nShipped in milestone 2.\n' >"$work/repo/docs/guide.md"
  commit_all "docs: update guide"
  expect pass "docs are not part of the code scan"
  expect fail "docs scan" --docs

  fixture
  printf '// helper\n' >>"$work/repo/internal/pkg/run.go"
  commit_all "fix(pkg): close F12 gap"
  expect pass "subjects ignored without --range"
  expect fail "labelled subject" --range HEAD~1..HEAD

  fixture
  expect fail "unknown argument" --bogus

  echo "naming-scan self-test: $passed passed, $failed failed"
  ((failed == 0))
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit
fi

cd "$(git rev-parse --show-toplevel)"
run_scan "$@"
