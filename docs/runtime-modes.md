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
one hour lease revoked on exit; Google and Microsoft token refreshes request their scopes and
verify the reply; GCP service account impersonation and Azure client credentials for one resource
check the lifetime and audience. A reply that does not match fails closed.

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
