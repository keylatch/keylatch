---
title: CI workload identity
---

# CI workload identity

A CI job proves who it is with the OIDC token its CI provider issues, instead of holding a long-lived Keylatch credential. `keylatch ci exchange` verifies that token against the trust entries in your `config.json` and limits the rest of the job to the connections the matching entry lists.

## Trust configuration

Add `ci.trust` to the operator's `config.json`:

```json
{
  "version": 1,
  "ci": {
    "trust": [
      {
        "provider": "github-actions",
        "audience": "keylatch-ci",
        "repositories": ["acme/app"],
        "refs": ["refs/heads/main", "refs/tags/v*"],
        "environments": ["production"],
        "job_workflow_refs": ["acme/app/.github/workflows/deploy.yml@refs/heads/main"],
        "connections": ["github-app"],
        "max_ttl": 900
      }
    ]
  }
}
```

A token is accepted only when every field that is set matches:

| Field | Meaning |
|-------|---------|
| `provider` | `github-actions` or `gitlab`. |
| `issuer`, `jwks_url` | Override the provider's issuer and key set URL (self-managed GitLab). Both must be https. |
| `audience` | Required. The token must carry exactly this audience. |
| `repositories` | Required. `owner/name` (the project path on GitLab); `*` matches one path segment. `*` alone is rejected. |
| `refs` | Required. Full refs: `refs/heads/main`, `refs/tags/v*`. The ref keeps its kind, so a tag named `main` never matches the branch `main`. A bare `main` is rejected. |
| `environments` | The deployment environment claim, when set. |
| `job_workflow_refs` | The `job_workflow_ref` claim (`ci_config_ref_uri` on GitLab), when set. |
| `connections` | Required. The only connections the session may use. |
| `max_ttl` | Session lifetime in seconds, 1-3600 (default 3600). The session also ends with the token. |

Verification fails closed: an unreachable key set, an unsigned or `alg: none` token, a missing `exp`, or a token whose signing key is not in the issuer's key set is refused.

## GitHub Actions

```yaml
permissions:
  id-token: write
  contents: read
steps:
  - uses: keylatch/keylatch/actions/setup@<commit sha>
    with:
      version: v0.13.0
      audience: keylatch-ci
  - run: keylatch run github-app -- gh api /repos/acme/app
```

`actions/setup` downloads the release you pin, verifies the cosign signature on its checksums and the archive's checksum, puts `keylatch` on `PATH`, and runs `keylatch ci exchange`. There is no "latest": a job that does not name a version fails.

The runner needs the connection's backend credentials from its own federation (below) and an operator config with the `ci.trust` entry.

## GitLab CI

```yaml
job:
  id_tokens:
    KEYLATCH_CI_ID_TOKEN:
      aud: keylatch-ci
  script:
    - keylatch ci exchange --provider gitlab --env-file "$CI_PROJECT_DIR/keylatch.env"
    - export "$(cat "$CI_PROJECT_DIR/keylatch.env")"
    - keylatch run github-app -- gh api /repos/acme/app
```

## What the exchange writes

`ci exchange` never prints a token or a secret. It writes a session record (provider, repository, ref, environment, connections, expiry; no secret) under `$RUNNER_TEMP/keylatch`, appends `KEYLATCH_CI_SESSION=<path>` to `$GITHUB_ENV` or `--env-file`, and prints one JSON line without values to standard error, which is the job log:

```json
{"event":"ci.exchange","outcome":"ok","provider":"github-actions","repository":"acme/app","ref":"refs/heads/main","connections":["github-app"],"expires":"2026-10-16T12:00:00Z"}
```

While `KEYLATCH_CI_SESSION` is set, `keylatch run` and the MCP `keylatch_run` tool refuse every connection outside the session and stop at its expiry. A session record that cannot be read denies everything. The variable only narrows what the job may do; unsetting it returns to the ordinary policy.

## Backend credentials

Add a `cloud` object to a trust entry to prepare the cloud SDK's workload identity credentials after Keylatch verifies the job token:

| Provider | `cloud` configuration | Exported variables |
| --- | --- | --- |
| AWS | `{"provider":"aws","role_arn":"arn:aws:iam::123456789012:role/ci","region":"eu-west-1"}` | `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN`, `AWS_ROLE_SESSION_NAME`, optional `AWS_REGION` |
| GCP | `{"provider":"gcp","workload_identity_provider":"//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/ci/providers/github","service_account":"ci@project.iam.gserviceaccount.com"}` | `GOOGLE_APPLICATION_CREDENTIALS` pointing to an external-account credential file; service-account impersonation is optional |
| Azure | `{"provider":"azure","tenant_id":"11111111-2222-3333-4444-555555555555","client_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}` | `AZURE_FEDERATED_TOKEN_FILE`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` |

The trust entry's audience must also be accepted by the cloud provider's federation configuration. Configure that provider to trust only the intended issuer, repository and job identity. Keylatch verifies its own trust rules first; the cloud SDK exchanges the token with the provider when it needs credentials. The provider still decides whether to grant access.

Each exchange writes its OIDC token into a separate private directory under the session directory, with a private token file. The GCP credential file contains a path to that token, not the token itself. Keep these files out of artifacts and caches and remove the runner's temporary directory after the job. Tokens and cloud credentials are never printed to the job log. The `aws-sm`, `gcp-sm` and `azure-kv` backends use these default credential chains; existing static environment credentials can take precedence in an SDK, so remove those when using federation.

Without `cloud`, configure the SDK's workload identity separately or use a machine account from the CI secret store.
