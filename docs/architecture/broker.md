# Token Broker Architecture

## Overview

The keylatch token broker is the component that mediates short-lived credential
exchanges between LLM sessions (actors) and registered provider strategies
(OAuth, AWS STS, GitHub App, etc.). It runs entirely in-process — there is no
separate broker daemon or socket.

## In-Process Model

The broker (`internal/broker.BrokerImpl`) is constructed once per process
lifetime via `broker.NewBroker(...)`. All token exchange, caching, and
revocation happen within the same OS process that called `NewBroker`.

```
┌───────────────────────────────────────────────────────────┐
│  keylatch process (e.g. gateway server or CLI with broker) │
│                                                           │
│  ┌───────────┐    Exchange    ┌─────────────────────────┐ │
│  │  Actor    │ ──────────────▶│  BrokerImpl             │ │
│  │  (LLM     │                │  ┌──────────────────┐   │ │
│  │   session)│ ◀──────────── │  │  tokenCache      │   │ │
│  └───────────┘   ExchangeResult│  └──────────────────┘   │ │
│                                │  ┌──────────────────┐   │ │
│                                │  │  strategies map  │   │ │
│                                │  │  (OAuth, STS...) │   │ │
│                                │  └──────────────────┘   │ │
│                                └─────────────────────────┘ │
└───────────────────────────────────────────────────────────┘
```

### Token cache

Exchanged tokens are held in an in-memory `tokenCache` (a bounded map protected
by `sync.RWMutex`). Tokens are never written to disk. The cache:

- Is bounded at 1000 entries (`DefaultMaxCacheEntries`).
- Evicts expired entries every 30 seconds via a background goroutine.
- Is flushed synchronously on vault lock (FIND2-004).

### Security invariants

- Token bytes are stored in unexported `cacheEntry.tokenBytes` fields.
- `ExchangeResult` carries tokens via `TokenBytes()` — never as a string field.
- All CLI output paths (`broker status`, `broker dry-run`, `broker revoke`)
  are value-free: only metadata (provider, HMAC-hashed actor, token ID, TTL)
  is emitted. Raw credential values never appear in any output.
- Actor and session IDs in audit events are HMAC-SHA256 hashed using a
  per-broker key — raw values are never logged.

## BrokerHandle: in-process vs out-of-process

CLI commands obtain a `BrokerHandle` via `broker.NewBrokerHandle(nil)`. This
factory detects whether a `BrokerImpl` was constructed in the current process
using an atomic singleton:

```go
// Set by NewBroker at construction time.
var currentBrokerPtr atomic.Pointer[BrokerImpl]

func NewBrokerHandle(b *BrokerImpl) BrokerHandle {
    if b != nil {
        return &inProcessHandle{b: b}
    }
    if cur := CurrentBroker(); cur != nil {
        return &inProcessHandle{b: cur}
    }
    return &outOfProcessHandle{}
}
```

### In-process handle

`inProcessHandle` delegates directly to the live `BrokerImpl`. Used by:

- `keylatch broker status` — lists live cache entries.
- `keylatch broker dry-run` — simulates an exchange without mutating the cache.
- `keylatch broker revoke` — evicts a cache entry and emits an audit event.

### Out-of-process handle

`outOfProcessHandle` returns `ErrBrokerOutOfProcess` from every method with
an actionable message:

```
broker: not running in-process — this CLI invocation does not own the broker.
Use the gateway process (keylatch gateway up) to exchange or revoke tokens,
or run this command from within the same process that constructed the broker.
```

CLI commands surface this as exit code 2 (`SecurityBlock`) so callers can
detect it programmatically.

## Split-brain: internal/broker vs internal/gateway/broker

The `internal/broker` package is the canonical Phase-13 in-process
implementation. `internal/gateway/broker` (if present) is a separate
gateway-side component that owns a different broker instance running inside the
gateway process.

Cross-process queries (CLI → gateway broker) are intentionally not supported
via the `BrokerHandle` interface. To inspect or manage tokens in a running
gateway, use `keylatch gateway status` and `keylatch gateway token revoke`.

This split is NOT resolved in EPIC-23. CLI broker commands target only the
in-process broker.

## Dry-run exchange

`BrokerHandle.DryRunExchange(provider, command)` simulates a token exchange:

1. Verifies the provider has a registered strategy.
2. Derives scopes from the `command` string (first binary name → `provider.binary`).
3. Runs a policy check (currently always `allow`; future phases will consult the
   policy engine).
4. Emits a `broker.dry_run_requested` audit event.
5. Returns a `DryRunResult` — no cache mutation, no provider call.

## Token revocation

`BrokerHandle.Revoke(tokenID)`:

1. Scans the cache for the entry whose `ScopedTokenID` matches.
2. Zeroes the token bytes and deletes the entry (holding the write lock).
3. Attempts provider-side revocation if the template declares a revocation
   endpoint (best-effort; logs on failure — does not block local revocation).
4. Emits a `broker.token_revoked` audit event with:
   - `token_id` — the opaque ID (not raw bytes)
   - `provider`
   - `actor_hmac` — HMAC-hashed actor
   - `timestamp`
   - `provider_revocation_attempted` / `provider_revocation_succeeded`

`BrokerHandle.RevokeAll(actorID)` lists all live grants and calls `Revoke` for
each. When `actorID` is empty, all grants are revoked regardless of actor. Race
conditions (entries expiring between listing and revoking) are tolerated: the
revoke loop skips `ErrTokenNotFound` silently.

## Audit events

| Action | When emitted |
|--------|-------------|
| `broker.exchange` | Fresh token exchange (cache miss) |
| `broker.cache_hit` | Token served from cache |
| `broker.dry_run_requested` | `DryRunExchange` called |
| `broker.token_revoked` | Token evicted via `Revoke` |

All events are written to the local audit log via `audit.Emitter`. Actor and
session IDs are HMAC-SHA256 hashed — raw values are never logged.
