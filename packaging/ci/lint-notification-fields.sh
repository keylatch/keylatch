#!/usr/bin/env bash
# packaging/ci/lint-notification-fields.sh
#
# CI lint: verify that struct fields on Notification (notify.rs),
# ApprovalEvent, ReceiptEvent, and SecurityEvent (events.go) are within
# the documented allow-list and have a "// security-reviewed: <date>" comment.
#
# Exit 0: clean tree.
# Exit 1: undocumented field found (add a "// security-reviewed: YYYY-MM-DD" comment
#          on the same line as the field declaration, or remove the field).
#
# Usage:
#   bash packaging/ci/lint-notification-fields.sh [repo-root]

set -euo pipefail

REPO_ROOT="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
NOTIFY_RS="${REPO_ROOT}/src-tauri/src/notify.rs"
EVENTS_GO="${REPO_ROOT}/internal/sidecar/events/events.go"

ERRORS=0

# ── Allowed Notification fields (spec §3.3) ───────────────────────────────────
NOTIFICATION_ALLOWED=(
  "id"
  "title"
  "body"
  "action_url"
  "urgency"
  "created_at"
  "expires_at"
)

# ── Allowed ApprovalEvent fields (spec §3.7) ─────────────────────────────────
APPROVAL_ALLOWED=(
  "ApprovalID"
  "approval_id"
  "Provider"
  "provider"
  "Action"
  "action"
  "Actor"
  "actor"
  "RequestedAt"
  "requested_at"
  "ExpiresAt"
  "expires_at"
  "DeepLinkPath"
  "deep_link_path"
)

# ── Allowed ReceiptEvent fields (spec §3.8) ───────────────────────────────────
RECEIPT_ALLOWED=(
  "ReceiptID"
  "receipt_id"
  "Actor"
  "actor"
  "Provider"
  "provider"
  "Action"
  "action"
  "Runtime"
  "runtime"
  "CredentialShape"
  "credential_shape"
  "PolicyDecision"
  "policy_decision"
  "TokenTTLLeft"
  "token_ttl_left"
  "StatusGroup"
  "status_group"
  "DurationMS"
  "duration_ms"
  "DeepLinkPath"
  "deep_link_path"
  "NoSecretsProof"
  "no_secrets_proof"
)

# ── Allowed SecurityEvent fields (from implementation) ───────────────────────
SECURITY_ALLOWED=(
  "EventID"
  "event_id"
  "Severity"
  "severity"
  "Kind"
  "kind"
  "Timestamp"
  "timestamp"
  "AuditRef"
  "audit_ref"
)

contains() {
  local needle="$1"
  shift
  local elem
  for elem in "$@"; do
    [[ "$elem" == "$needle" ]] && return 0
  done
  return 1
}

check_rust_struct() {
  local file="$1"
  local struct_name="$2"
  shift 2
  local allowed=("$@")

  local in_struct=false
  local lineno=0

  while IFS= read -r line; do
    lineno=$((lineno + 1))

    # Detect struct start.
    if echo "$line" | grep -qE "^pub struct ${struct_name}\b"; then
      in_struct=true
      continue
    fi

    # Detect struct end.
    if $in_struct && echo "$line" | grep -qE "^}"; then
      in_struct=false
      continue
    fi

    if $in_struct; then
      # Extract field name from "pub <name>: <type>" pattern.
      local field
      field=$(echo "$line" | sed -n 's/^[[:space:]]*pub \([a-z_][a-z_0-9]*\):.*/\1/p')
      if [[ -z "$field" ]]; then
        continue
      fi

      if ! contains "$field" "${allowed[@]}"; then
        # Field is not in the allow-list — require a security-reviewed comment.
        if ! echo "$line" | grep -q "security-reviewed:"; then
          echo "ERROR: ${file}:${lineno}: field '${field}' on ${struct_name} is not in the allow-list and lacks '// security-reviewed: <date>' comment"
          ERRORS=$((ERRORS + 1))
        fi
      fi
    fi
  done < "$file"
}

check_go_struct() {
  local file="$1"
  local struct_name="$2"
  shift 2
  local allowed=("$@")

  local in_struct=false
  local lineno=0

  while IFS= read -r line; do
    lineno=$((lineno + 1))

    if echo "$line" | grep -qE "^type ${struct_name} struct"; then
      in_struct=true
      continue
    fi

    if $in_struct && echo "$line" | grep -qE "^}"; then
      in_struct=false
      continue
    fi

    if $in_struct; then
      # Extract field name from "FieldName <type> ..." pattern.
      local field
      field=$(echo "$line" | sed -n 's/^[[:space:]]*\([A-Z][a-zA-Z0-9_]*\)[[:space:]].*/\1/p')
      if [[ -z "$field" ]]; then
        continue
      fi

      if ! contains "$field" "${allowed[@]}"; then
        if ! echo "$line" | grep -q "security-reviewed:"; then
          echo "ERROR: ${file}:${lineno}: field '${field}' on ${struct_name} is not in the allow-list and lacks '// security-reviewed: <date>' comment"
          ERRORS=$((ERRORS + 1))
        fi
      fi
    fi
  done < "$file"
}

# ── Check Rust notify.rs ──────────────────────────────────────────────────────
if [[ -f "$NOTIFY_RS" ]]; then
  check_rust_struct "$NOTIFY_RS" "Notification" "${NOTIFICATION_ALLOWED[@]}"
else
  echo "ERROR: ${NOTIFY_RS} not found — required source file is missing (N5)"
  ERRORS=$((ERRORS + 1))
fi

# ── Check Go events.go ────────────────────────────────────────────────────────
if [[ -f "$EVENTS_GO" ]]; then
  check_go_struct "$EVENTS_GO" "ApprovalEvent" "${APPROVAL_ALLOWED[@]}"
  check_go_struct "$EVENTS_GO" "ReceiptEvent"  "${RECEIPT_ALLOWED[@]}"
  check_go_struct "$EVENTS_GO" "SecurityEvent" "${SECURITY_ALLOWED[@]}"
else
  echo "ERROR: ${EVENTS_GO} not found — required source file is missing (N5)"
  ERRORS=$((ERRORS + 1))
fi

if [[ $ERRORS -gt 0 ]]; then
  echo "FAIL: ${ERRORS} undocumented field(s) found. Add '// security-reviewed: $(date +%Y-%m-%d)' comment or update the allow-list."
  exit 1
fi

echo "OK: notification field allow-list check passed"
