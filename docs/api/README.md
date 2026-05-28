# keylatchd HTTP API

The `openapi.yaml` file in this directory documents every HTTP route exposed by
the `keylatchd` sidecar process (bound to `127.0.0.1:7890` by default).

## What this spec covers

| Path | Methods | Purpose |
|------|---------|---------|
| `/health` | GET | Liveness probe (no auth required) |
| `/v1/health` | GET | Liveness probe — versioned alias |
| `/v1/health/readiness` | GET | Readiness probe with per-check detail |
| `/v1/status` | GET | Session status and backend info |
| `/v1/connections` | GET | List stored credential connections (metadata only) |
| `/v1/backends` | GET | List registered backends and availability |
| `/v1/providers` | GET | List provider templates with connection status |
| `/v1/connect` | POST | Store a credential (CSRF required) |
| `/v1/agent/setup` | POST | Write agent profile config (CSRF required) |
| `/v1/receipts` | GET, POST | Runtime receipt log (value-free) |
| `/v1/receipts/stream` | GET | SSE stream of runtime receipts |
| `/v1/approvals` | GET | List approval requests |
| `/v1/approvals/stream` | GET | SSE stream of approval requests |
| `/v1/approvals/{id}` | GET, POST | Get or decide a specific approval |
| `/v1/approvals/{id}/approve` | POST | Approve shorthand (no body required) |
| `/v1/approvals/{id}/deny` | POST | Deny shorthand (no body required) |

## Stability warning

**Unstable: subject to change pre-1.0.**

All endpoints carry `x-stability: internal`. The API surface is internal to the
keylatchd process and the Keylatch browser UI. No backwards-compatibility
guarantees are made before the 1.0.0 release.

## Render locally

To render the spec as interactive HTML documentation using Redoc:

```bash
npx @redocly/cli preview-docs docs/api/openapi.yaml
```

This starts a local server (typically at `http://localhost:8080`) with full
request/response examples.

Alternatively, use the Swagger UI:

```bash
npx @stoplight/spectral-cli lint docs/api/openapi.yaml
```

## Linting

The spec is linted in CI using Spectral. To lint locally:

```bash
npx --yes @stoplight/spectral-cli lint docs/api/openapi.yaml
```

A zero-exit means the spec is valid OpenAPI 3.1 and passes all built-in rules.

## Authentication

- **Session cookie** (`KEYLATCH_SESSION`): required on all endpoints except
  `GET /health` and `GET /v1/health`.
- **CSRF token** (`X-Keylatch-CSRF`): required on all state-mutating `POST`
  endpoints. Obtain a token from `GET /api/csrf`.

Both are issued automatically by `keylatch ui` when the browser session is
established via the bootstrap URL.
