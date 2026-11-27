# Runtime Modes

Keylatch has these runtime modes, which decide how a credential reaches a subprocess. Use
`--runtime <mode>` with `keylatch run`. A name that is not a mode fails with
`unknown runtime mode`.

## The modes

| Mode | Status | Description |
|------|--------|-------------|
| `gateway_typed` | Supported | Routes execution through the local Keylatch gateway. The default. Requires `keylatch gateway up`. |
| `gateway_sdk` | Supported | Routes execution through the gateway using the OpenAI-compatible SDK routes. Requires `keylatch gateway up`. |
| `minted` | Supported | Runs the command with a credential Keylatch mints for it and revokes when it exits: a GitHub App installation token for one repository, or an endpoint for AWS STS credentials limited by a session policy. See [Minted credentials](#minted-credentials). |
| `contained` | Supported (Linux) | Tier D5. The daemon runs the command in a Keylatch sandbox and gives it the real value; see [contained-runtime.md](contained-runtime.md). Selected with `--tier D5`, not `--runtime`. |
| `gateway_proxy` | Unavailable | Routes HTTPS traffic through a local proxy that rewrites `Authorization` headers. Excluded from this release until its redirect, authority and credential-boundary fixes land. |

`direct_brokered` is now `minted`; `--runtime direct_brokered` exits 5 and names the new mode. The
`direct_classic_sandboxed` mode was removed; it is not a mode and no alias remains.

Without `--runtime`, a connection uses the mode its template prefers. A template that lists no
preference falls back to `gateway_typed`.

The support manifest is the single source for which modes are enabled. `keylatch scope` prints it.

## Minted credentials

`--runtime minted` mints a credential for one command and revokes it when the command exits. The
command's environment holds `PATH`, `HOME`, the locale variables, `KEYLATCH_RUNTIME` and the
variables the template's injection rules name, and nothing else from the parent. The stored root
credential is never read for the command, so a template with only static fields refuses `minted`.
Agent sessions are refused: the command holds a usable credential.

- **GitHub App** (`github-app`): `keylatch run github-app --runtime minted -- gh api …` sets
  `GH_TOKEN` and `GITHUB_TOKEN` to an installation token for the one repository and the
  permissions the connection's `mint.github_app` policy allows. The policy's `callers` lists the
  caller kinds that may do this (service and host by default). GitHub's reply must match the
  request or the token is revoked and the run fails.
- **AWS** (`aws`): the policy in `mint.aws` names the role (`role_arn`), an IAM session policy
  (`session_policy`, required) and the session length (`max_ttl`, 900 to 3600 seconds, default
  900). The command gets `AWS_CONTAINER_CREDENTIALS_FULL_URI` and
  `AWS_CONTAINER_AUTHORIZATION_TOKEN`; the AWS CLI and SDKs fetch credentials from that loopback
  endpoint, which assumes the role with the session policy, checks that STS returned that role
  session and refreshes shortly before expiry. The endpoint and its token end with the command.
  The connection needs `access_key_id` and `secret_access_key` of a key that may assume the role.
- **HashiCorp Vault** (`hashicorp-vault`): `mint.vault` names one dynamic-secret `path` (for
  example `database/creds/readonly`) and `max_ttl` (1 to 3600 seconds, default 3600). The command
  gets the fields the lease carries: `VAULT_SECRET_USERNAME` and `VAULT_SECRET_PASSWORD` for a
  database engine, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` for the AWS
  engine. A reply with no lease, a lease longer than `max_ttl`, or none of those fields is revoked
  and refused. The lease is revoked when the command exits. The connection needs `vault_addr`
  (https, or loopback) and `vault_token`, a token that may read the path and revoke its leases.
- **Google Cloud** (`gcp`): `mint.gcp` names the `service_account` to impersonate, the OAuth
  `scopes` a token may carry and `max_ttl` (1 to 3600 seconds, default 3600). The command gets
  `GCE_METADATA_HOST`, pointing to a loopback metadata endpoint with an unguessable session path.
  Metadata clients retrieve the account's scoped token from that endpoint; no access token is
  injected into the environment. The connection holds `service_account_key`, the key file of an identity
  that has only the Service Account Token Creator role on the target. Keylatch introspects the
  issued token with Google's tokeninfo API and refuses mismatched scopes or expiry; an unavailable
  introspection endpoint also refuses the mint.
- **Azure** (`azure`): `mint.azure` names the `resource` and `max_ttl` (1 to 5400 seconds, default
  3600). The command gets `IDENTITY_ENDPOINT` and `IDENTITY_HEADER`, selecting the Azure SDK's
  managed-identity endpoint protocol. It serves a token only for the configured resource.
  Entra ID picks the token lifetime (60 to 90 minutes by default); a token that lives
  longer than `max_ttl` is refused, so an operator who accepts Entra's lifetime sets 5400. The
  connection holds `tenant_id`, `client_id` and `client_secret`. For workload identity federation,
  set `mint.azure.authentication` to `federated` and supply `client_assertion`, a short-lived JWT
  issued by the external identity provider registered in Entra ID. Keylatch sends that assertion
  to Entra's token endpoint with the JWT-bearer assertion type, never a client secret. A missing
  or refused assertion fails; it does not fall back to another authentication method.
- **OAuth refresh token** (`oauth-refresh`): `mint.oauth` names the provider's `token_endpoint`
  (https), the `scopes` a token may carry and `max_ttl` (1 to 5400 seconds, default 3600). The
  command gets `OAUTH_ACCESS_TOKEN`. The provider's reply must report exactly the requested scopes
  and an explicit positive expiry no longer than `max_ttl`. The connection holds `client_id`, `client_secret`
  and `refresh_token`.

The GCP and Azure endpoints end when the command exits, its context is canceled, or the minted
token expires. Every token response requires a successful audit write. They refuse other hosts,
session paths, identity selectors, scopes and resources; they do not refresh indefinitely.
Fetched tokens remain valid until provider expiry, and the output guard masks them if the child
prints them. `keylatch mint` still returns the scoped token directly. SDK default credential chains
may prefer credentials already present in the user's home directory; select metadata or managed
identity credentials explicitly when that distinction matters. These endpoints provide SDK
compatibility, not filesystem isolation.

GCP, Azure and OAuth tokens cannot be revoked by Keylatch; they end at their expiry, so keep
`max_ttl` short. Vault leases and GitHub tokens are revoked on exit. For every provider the policy
lists `callers` (service and host by default; agent sessions never).

`keylatch mint <connection> --scope <key>=<value>` mints the same credentials without running a
command and prints them as JSON: `--scope repo=` and `--scope <permission>=<level>` for
`github-app`, `--scope scope=` (repeatable) for `gcp` and `oauth-refresh`, `--scope resource=` for
`azure`, `--scope path=` for `hashicorp-vault`, and `--scope role_arn=` plus `--scope duration=`
(seconds) for `aws`. AWS always uses the operator's session policy and role; only its duration
can be reduced, down to 900 seconds. Its JSON `data` contains `access_key_id`, `secret_access_key`
and `session_token`, and `scope` records the role, duration and session policy. A scope can narrow what the policy allows and never
widen it. A Vault lease printed this way is not revoked, because the credential is handed to the
caller; it ends within the hour.

```json
{
  "connections": {
    "aws": {
      "mint": {
        "aws": {
          "role_arn": "arn:aws:iam::123456789012:role/Reader",
          "session_policy": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}]},
          "max_ttl": 900
        }
      }
    }
  }
}
```

Every mint writes one `mint` audit event with `runtime` `minted` and no credential. Without a
writable audit log nothing is minted.

The provider strategies behind `minted` check what they receive. AWS STS requires a session
policy and verifies the assumed-role session and expiry; Vault dynamic secrets are limited to a
one hour lease revoked on exit; OAuth refreshes request their scopes and verify the reply; GCP
service account impersonation verifies the token's scopes and lifetime through introspection;
Azure client credentials check the lifetime and audience. Credential requests never follow
redirects. A reply that does not match fails closed. Real runs against Vault, Google Cloud,
Azure and an OAuth provider need an account; the strategies are tested against stub servers.

## Remote MCP servers

`keylatch mcp proxy <connection> --url <remote MCP URL>` is an MCP stdio server that forwards to
a remote Streamable HTTP MCP server and adds the connection's token as the header its slot names,
so the agent's MCP configuration holds a connection name and a URL and no token:

```json
{"mcpServers": {"remote": {"command": "keylatch", "args": ["mcp", "proxy", "remote-mcp", "--url", "https://mcp.example.com/mcp"]}}}
```

The URL must be https on a host the connection's header slot is bound to; redirects are not
followed. The connection's policy is checked before the first request, every request is audited
as a `call` event named `mcp.<method>`, and an answer that repeats the token is redacted.

## The gateway invariant

In every gateway mode the child process receives a short-lived Keylatch session token and a
gateway URL, never the provider key. The gateway sends the provider key only to the allowlisted
provider.

## Agent sessions

When Keylatch detects an agent session (`CLAUDECODE=1`, `CODEX_SANDBOX` set, a harness ancestor, a
session ticket), the gateway modes stay available. `keylatch get` is always refused in an agent
session (exit code 2). Detection is a label, not a security boundary; see
[Security](security.md).

## Credential storage path

Credentials are stored at the four-segment path:

```
<namespace>/<category>/<provider>/<field>
```

For example `default/ai/openrouter/api_key`. The path format is the same for every backend, CLI
command and gateway vault lookup.

## Gateway token constraints

The token `keylatch gateway token create` prints is a constrained bearer token:

- **TTL**: it expires after the declared `--ttl` (default `1h`); an expired token returns `401 token_expired`.
- **Scope**: each token names the capabilities it may use, such as `openrouter.chat.completion`; a route outside that scope returns `403 capability_mismatch`.
- **Audience**: the capability format `<provider>.<action>` ties a token to one provider; a token for `openrouter` cannot be used on `sentry` routes.
- **Replay protection**: a token created with `--max-uses N` is accepted at most N times; the next request returns `401 token_exhausted`.
- **Revocation**: `keylatch gateway token revoke` ends a token; a revoked token returns `401 token_revoked`.

## SDK route resolution

For providers whose template declares `GatewayActions` with an explicit `sdk_path`, the gateway
registers the route at that path. Without an `sdk_path` it synthesizes
`/sdk/<provider>/v1/<action>`. The synthesized path is not registered when an explicit one exists.

```
sdk_path: /v1/chat/completions  ->  POST /v1/chat/completions
sdk_path: /v1/models            ->  GET  /v1/models
```

## Diagnosing mode availability

```bash
keylatch runtime doctor <provider>
keylatch runtime doctor openrouter --json
```

The report says, for each mode, whether the provider supports it and whether it is available given
the current state (for example, whether the gateway is running).
