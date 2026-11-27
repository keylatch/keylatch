# Mint conformance testing

`keylatch mint` asks GitHub for an installation token limited to one repository and the permissions you list, and checks the reply before it trusts it: the repository and permissions must equal the request and the lifetime must not exceed `max_ttl`, or the token is revoked and the mint fails. This page covers how to test that against a stub or against GitHub itself.

## The test endpoint build

The default `keylatch` talks to `https://api.github.com` and nothing can change that: no environment variable, no flag. To run a mint against a stub GitHub server there is a second build, made with the Go build tag `mint_test_endpoint`:

```bash
go build -tags mint_test_endpoint -o keylatch-testendpoint ./cmd/keylatch
KEYLATCH_TEST_GITHUB_API_URL=http://127.0.0.1:8099 ./keylatch-testendpoint mint ...
```

In that build `KEYLATCH_TEST_GITHUB_API_URL` replaces the API root for every GitHub App request (token minting, revocation), whatever base a caller passed. Without the variable it talks to GitHub. `keylatch version` ends with `testendpoint` (and `--json` carries `"Variant": "testendpoint"`), so it cannot be mistaken for a release.

Releases publish it as `keylatch-testendpoint_<version>_linux_amd64.tar.gz`. It is listed in the checksums file, signed with cosign like the other archives, and its release note says it is for conformance testing only. It is not in the packages or the container images. Do not run it with real credentials: whoever controls the variable receives the App's signed JWT.

Two tests keep the line between the builds:

```bash
go test ./internal/broker/strategies/ -run '^TestDefaultBuildIgnoresEndpointOverride$'
go test -tags mint_test_endpoint ./internal/broker/strategies/ -run '^TestTestBuildHonorsEndpointOverride$'
```

## What a stub must answer

`POST /app/installations/{id}/access_tokens` with a JSON body naming one repository and the permissions, answered with `token`, `expires_at`, `repositories` and `permissions`; and `DELETE /installation/token` for the revocation after a mismatch. A reply that names a different repository, wider permissions or a longer lifetime must make `keylatch mint` exit 5 after revoking the token.

## The nightly smoke run

`.github/workflows/mint-smoke.yml` mints a `contents: read` token for one real test repository every night with the default build and checks, with `scripts/mint-smoke.sh`, that the output has exactly `token`, `expires_at`, `repository` and `permissions`, that the scope is what was asked for, and that GitHub lists only that repository for the token. It revokes the token afterwards and never prints it.

It needs a GitHub App installed on the test repository only, and these repository secrets:

| Secret | Value |
|--------|-------|
| `MINT_SMOKE_APP_ID` | the App's ID |
| `MINT_SMOKE_INSTALLATION_ID` | the installation on the test repository's owner |
| `MINT_SMOKE_PRIVATE_KEY` | the App's private key (PEM) |
| `MINT_SMOKE_REPO` | `owner/name` of the test repository |

Without them the run ends with a notice and passes. Run `scripts/mint-smoke.sh <keylatch binary>` yourself only on a throwaway machine: it rewrites the operator's config file.
