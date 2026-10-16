#!/usr/bin/env bash
# Mints a contents:read installation token for the one test repository with the
# given keylatch binary and checks the JSON shape and the scope. Run it only on
# an ephemeral CI runner: it writes the operator's config file and a throwaway
# vault, and it needs real GitHub App credentials in the environment:
#
#   MINT_SMOKE_APP_ID            the App's ID
#   MINT_SMOKE_INSTALLATION_ID   the installation on the test repository's owner
#   MINT_SMOKE_PRIVATE_KEY       the App's private key (PEM)
#   MINT_SMOKE_REPO              owner/name of the one test repository
#
# The token is never printed. It is revoked at the end.
set -euo pipefail

bin="${1:?usage: mint-smoke.sh <path to keylatch>}"
app_id="${MINT_SMOKE_APP_ID:?}"
installation_id="${MINT_SMOKE_INSTALLATION_ID:?}"
private_key="${MINT_SMOKE_PRIVATE_KEY:?}"
repo="${MINT_SMOKE_REPO:?}"
owner="$(printf '%s' "${repo%%/*}" | tr '[:upper:]' '[:lower:]')"
connection=github-app

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$here/ci-operator-config.sh"
config="$HOME/.config/keylatch/config.json"
[[ "$(uname -s)" == Darwin ]] && config="$HOME/.keylatch/config.json"

# The mint policy lives in the operator's config file and nowhere else.
tmp="$(mktemp)"
jq --arg c "$connection" --arg repo "$repo" \
  '.connections[$c].mint.github_app = {callers: ["human", "service", "host"], allow_repos: [$repo], permission_ceiling: {contents: "read"}, max_ttl: 600}' \
  "$config" >"$tmp"
mv "$tmp" "$config"
chmod 600 "$config"

"$bin" bootstrap >/dev/null
"$bin" policy init >/dev/null
printf '%s' "$private_key" | "$bin" connect "$connection" --non-interactive --no-test \
  -f private_key=@- -f "app_id=$app_id" -f "installation_$owner=$installation_id" >/dev/null

reply="$("$bin" mint "$connection" --repo "$repo" --permission contents=read --format json)"

token="$(jq -r '.token' <<<"$reply")"
trap 'curl -sS -o /dev/null -X DELETE -H "Authorization: Bearer $token" -H "Accept: application/vnd.github+json" https://api.github.com/installation/token || true' EXIT

fail() { echo "mint-smoke: $*" >&2; exit 1; }

keys="$(jq -r 'keys | join(",")' <<<"$reply")"
[[ "$keys" == "expires_at,permissions,repository,token" ]] || fail "unexpected fields: $keys"
[[ -n "$token" && "$token" != null ]] || fail "empty token"
[[ "$(jq -r '.repository' <<<"$reply")" == "$repo" ]] || fail "token is not scoped to $repo"
[[ "$(jq -c '.permissions' <<<"$reply")" == '{"contents":"read"}' ]] || fail "unexpected permissions: $(jq -c '.permissions' <<<"$reply")"
expires="$(jq -r '.expires_at' <<<"$reply")"
[[ "$(date -u -d "$expires" +%s)" -gt "$(date -u +%s)" ]] || fail "token already expired ($expires)"

# GitHub itself must agree about the scope.
repos="$(curl -sS -H "Authorization: Bearer $token" -H "Accept: application/vnd.github+json" https://api.github.com/installation/repositories)"
[[ "$(jq -r '[.repositories[].full_name] | join(",")' <<<"$repos")" == "$repo" ]] || fail "the token reaches more than $repo"

echo "mint-smoke: minted a contents:read token for $repo, expires $expires"
