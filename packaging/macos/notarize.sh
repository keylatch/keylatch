#!/usr/bin/env bash
# packaging/macos/notarize.sh — macOS notarisation wrapper.
#
# Submits the Keylatch.app bundle (or DMG) to Apple's notarisation service
# using xcrun notarytool. Credentials are read exclusively from environment
# variables — never hardcoded in this script.
#
# Required environment variables:
#   APPLE_ID          — Apple developer account email
#   APPLE_TEAM_ID     — 10-character Apple team ID
#   APPLE_APP_PASSWORD — app-specific password (not your Apple ID password)
#
# Optional:
#   KEYLATCH_ARTIFACT — path to the .dmg or .app.zip to notarise
#                       (defaults to "Keylatch.dmg" in the current directory)
#
# Usage:
#   bash packaging/macos/notarize.sh [path/to/artifact]

set -euo pipefail

ARTIFACT="${1:-${KEYLATCH_ARTIFACT:-Keylatch.dmg}}"
BUNDLE_ID="com.keylatch.app"

# Validate required environment variables.
: "${APPLE_ID:?ERROR: APPLE_ID is not set. Set it to your Apple developer email.}"
: "${APPLE_TEAM_ID:?ERROR: APPLE_TEAM_ID is not set. Set it to your 10-character team ID.}"
: "${APPLE_APP_PASSWORD:?ERROR: APPLE_APP_PASSWORD is not set. Generate one at appleid.apple.com.}"

if [[ ! -f "${ARTIFACT}" ]]; then
  echo "ERROR: artifact not found: ${ARTIFACT}" >&2
  exit 1
fi

echo "Submitting ${ARTIFACT} for notarisation (bundle-id: ${BUNDLE_ID})..."

xcrun notarytool submit "${ARTIFACT}" \
  --apple-id "${APPLE_ID}" \
  --team-id "${APPLE_TEAM_ID}" \
  --password "${APPLE_APP_PASSWORD}" \
  --bundle-id "${BUNDLE_ID}" \
  --wait

echo "Stapling notarisation ticket to ${ARTIFACT}..."
xcrun stapler staple "${ARTIFACT}"
echo "Notarisation complete."
