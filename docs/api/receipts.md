# API: Receipts

The receipts API exposes the in-memory ring buffer of `RuntimeReceipt` events emitted by the agent runtime. All payloads are **value-free** — credential bytes never appear (S-RM-9).

Server base URL: `http://127.0.0.1:7890` (configurable via `--bind`).

---

## GET /v1/receipts

Returns the last N receipts from the ring buffer as a JSON object.

### Query parameters

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | integer | `20` | `100` | Number of receipts to return (oldest-first within the window) |

### Response

**200 OK**

```json
{
  "receipts": [
    {
      "runtime": "gateway_typed",
      "provider": "anthropic",
      "capability": "messages",
      "policy_decision": "allowed",
      "credential_shape": "bearer",
      "exit_code": 0,
      "ttl": 30000000000
    }
  ]
}
```

**Receipt object fields**

| Field | Type | Description |
|-------|------|-------------|
| `runtime` | string | Runtime mode (e.g. `gateway_typed`, `direct_brokered`) |
| `provider` | string | Provider identifier (e.g. `anthropic`, `openai`) |
| `capability` | string | Capability requested (e.g. `messages`, `embed`) |
| `policy_decision` | string | Policy outcome (`allowed`, `denied`, `grant:<id>`) |
| `credential_shape` | string | Shape of credential used (e.g. `bearer`) — **never the credential value itself** |
| `exit_code` | integer | Process exit code; absent (0) on success |
| `ttl` | integer | TTL in nanoseconds (`time.Duration`); absent when not applicable |

**400 Bad Request** — `limit` is not a positive integer.

### Example

```bash
curl http://127.0.0.1:7890/v1/receipts?limit=10
```

---

## GET /v1/receipts/stream

Server-Sent Events (SSE) endpoint. The client receives a stream of receipt events in real time.

### Event types

| Event | Description |
|-------|-------------|
| `heartbeat` | Keepalive event sent on connection and every 15 seconds |
| `receipt` | A new `RuntimeReceipt` was pushed to the ring buffer |

### Receipt event payload

The `data` field of a `receipt` event is a JSON object with the same schema as the objects returned by `GET /v1/receipts`:

```
event: receipt
data: {"runtime":"gateway_typed","provider":"anthropic","capability":"messages","policy_decision":"allowed","credential_shape":"bearer","exit_code":0}

```

### Heartbeat event payload

```
event: heartbeat
data: {"time":"2026-05-18T12:00:00Z"}

```

### Client example (JavaScript)

```javascript
const es = new EventSource('/v1/receipts/stream')

es.addEventListener('receipt', (event) => {
  const receipt = JSON.parse(event.data)
  console.log(receipt.provider, receipt.capability, receipt.policy_decision)
})

es.addEventListener('heartbeat', () => {
  // Connection is alive — no action needed.
})
```

### Notes

- The connection is long-lived; clients should handle reconnection on error.
- The Dashboard SPA falls back to 5-second polling when `EventSource` is unavailable.
- Polling pauses while the browser tab is hidden (`document.visibilityState === 'hidden'`).
- The endpoint requires an active session cookie (enforced by `requireSession` middleware).

---

## POST /v1/receipts

Internal IPC endpoint used by the `keylatch` CLI to push receipts into the keylatchd ring buffer. Not intended for external callers.

### Security

Requires the `X-Keylatch-IPC-Secret` header to match the server's startup-time secret (S-INV-12). Requests without the correct secret are rejected with `401 Unauthorized`.

### Request body

Same JSON schema as the receipt object above.

### Responses

| Status | Meaning |
|--------|---------|
| `204 No Content` | Receipt accepted and stored |
| `400 Bad Request` | Malformed JSON body |
| `401 Unauthorized` | Missing or incorrect IPC secret |
| `405 Method Not Allowed` | Non-POST method |

---

## Security invariants

| Invariant | Description |
|-----------|-------------|
| S-RM-9 | Receipt payloads never contain credential values. Only metadata fields (`runtime`, `provider`, `capability`, `policy_decision`, `credential_shape`) are emitted. |
| S-INV-12 | `POST /v1/receipts` enforces constant-time IPC secret comparison to prevent foreign processes from injecting fake receipts. |
