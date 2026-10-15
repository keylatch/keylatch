# Runtime Modes

Keylatch has three runtime modes that decide how a credential reaches a subprocess. Use
`--runtime <mode>` with `keylatch run`. A name that is not a mode fails with
`unknown runtime mode`.

## The modes

| Mode | Status | Description |
|------|--------|-------------|
| `gateway_typed` | Supported | Routes execution through the local Keylatch gateway. The default. Requires `keylatch gateway up`. |
| `gateway_sdk` | Supported | Routes execution through the gateway using the OpenAI-compatible SDK routes. Requires `keylatch gateway up`. |
| `gateway_proxy` | Unavailable | Routes HTTPS traffic through a local proxy that rewrites `Authorization` headers. Excluded from this release until its redirect, authority and credential-boundary fixes land. |

`direct_brokered`, which exchanged a root credential for a scoped one inside the CLI, is also
Unavailable. v0.13.0 rebuilds it as `minted`. The `direct_classic_sandboxed` mode was removed; it
is not a mode and no alias remains.

The support manifest is the single source for which modes are enabled. `keylatch scope` prints it.

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
