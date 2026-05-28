# Runtime Modes

Keylatch supports five runtime modes that control how credentials are injected into subprocesses. Use `--runtime <mode>` with `keylatch run`.

## Available Modes (v1.0.0)

| Mode | Description |
|------|-------------|
| `gateway_typed` | Routes execution through the local keylatch gateway. Preferred for LLM sessions. Requires `keylatch gateway up`. |
| `gateway_sdk` | Routes execution through the gateway using the OpenAI-compatible SDK proxy. Requires `keylatch gateway up`. |
| `direct_brokered` | Exchanges credentials via a broker strategy (ephemeral tokens). No gateway required. |
| `gateway_proxy` | Routes HTTPS traffic through a local MITM proxy that rewrites Authorization headers. Requires local CA trust installation. |
| `direct_classic_sandboxed` | Injects raw credentials into a sandboxed subprocess (bwrap on Linux, sandbox-exec on macOS). `~/.keylatch/` is deny-listed inside the sandbox. See [Sandbox mode](./sandbox.md). |

## LLM Session Restrictions

When keylatch detects an LLM session (e.g. `CLAUDE_CODE=1`, `CODEX_ENV` set), all five modes are permitted without restriction. Raw credential values are never returned to the agent process outside the sandboxed child environment.

`keylatch get` is always blocked in LLM sessions (exit 2, SecurityBlock).

## Credential Storage Path (S-FIND-23)

All credentials are stored at the canonical four-segment path:

```
<namespace>/<category>/<provider>/<field>
```

Example:

```
default/ai/openrouter/api_key
```

This path format applies uniformly to all backends, CLI commands, and gateway vault lookups. There is no legacy `connections/` prefix — v1.0.0 has no existing users requiring backward compatibility.

## Gateway Token Constraints (EPIC-04)

The `KEYLATCH_GATEWAY_TOKEN` (or the JWT produced by `gateway token create`) is a constrained bearer token with the following security properties:

- **TTL**: Tokens expire after the declared `--ttl` (default `1h`). Expired tokens return `401 token_expired`.
- **Scope / Capability**: Each token declares the capabilities it may exercise (e.g. `openrouter.chat.completion`). Requests to routes outside that scope return `403 capability_mismatch`.
- **Audience isolation**: Capability format `<provider>.<action>` enforces provider-level audience — a token for `openrouter` cannot be used on `sentry` routes.
- **Replay protection**: Tokens with `--max-uses N` are accepted at most N times. Subsequent requests return `401 token_exhausted` (FIND3-009).
- **Revocation / Session end**: Tokens can be revoked with `gateway token revoke`. Revoked tokens return `401 token_revoked`.

## SDK Route Resolution (EPIC-04)

For providers that declare `GatewayActions` with an explicit `sdk_path` in their template, the gateway registers the route at the declared path. When no `sdk_path` is set, the gateway synthesizes a fallback path of the form `/sdk/<provider>/v1/<action>`.

Example (openai template):

```
sdk_path: /v1/chat/completions  →  POST /v1/chat/completions
sdk_path: /v1/models            →  GET  /v1/models
```

The synthesized fallback is NOT registered when an explicit `sdk_path` is declared.

## Diagnosing Mode Availability

```bash
keylatch runtime doctor <provider>
keylatch runtime doctor openrouter --json
```

Example output:

```
runtime doctor — provider: openrouter

  [ok  ] gateway_typed: gateway running (preferred mode)
  [ok  ] gateway_sdk: gateway running
  [ok  ] direct_brokered: supported
  [ok  ] gateway_proxy: gateway running
  [ok  ] direct_classic_sandboxed: sandbox primitive available: sandbox-exec built-in (macOS)
```

For sandbox-specific diagnostics use `keylatch sandbox doctor` (see [Sandbox mode](./sandbox.md)).
