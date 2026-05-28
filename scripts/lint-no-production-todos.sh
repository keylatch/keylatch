#!/usr/bin/env bash
set -euo pipefail

# Allowlist: files excluded from the production TODO/FIXME/XXX check.
# Each entry must have a reason comment explaining why the file is excluded.
#
# registry_scaffold_cmd.go  — scaffold template: TODOs are intentional placeholder
#                             text emitted into generated code for users to fill in.
# embed_loader.go           — embedded template content: literal TODO strings appear
#                             in scaffold output blobs, not as action items.
# verify.go                 — registry verify: TODOs are part of user-facing template
#                             validation messages shown to registry consumers.
# cmd/registry/validate.go  — registry validate: same as verify.go — user-facing
#                             validation message text, not action items.
# jcs.go                    — JCS (JSON Canonicalization Scheme): TODO appears in
#                             spec-quoted comment text copied verbatim from RFC 8785.
# help_topics.go            — help topics: TODO appears in user-visible help text
#                             examples, not as an internal action item.
# metrics.go                — telemetry doc comments use "KL-XXXX" as an error-code
#                             format placeholder (like KL-1234), not as an action item.

hits=$(grep -rEn 'TODO|FIXME|XXX' internal/ cmd/ --include="*.go" \
  | grep -v '_test.go' \
  | grep -v 'internal/cli/registry_scaffold_cmd.go' \
  | grep -v 'internal/registry/embed_loader.go' \
  | grep -v 'internal/registry/verify.go' \
  | grep -v 'internal/cmd/regvalidate/validate.go' \
  | grep -v 'internal/crypto/jcs/jcs.go' \
  | grep -v 'internal/cli/help_topics.go' \
  | grep -v 'internal/telemetry/metrics.go' \
  || true)
if [[ -n "$hits" ]]; then
  echo "Production TODO/FIXME/XXX found:"
  echo "$hits"
  exit 1
fi
echo "No production TODOs found."
