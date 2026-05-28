---
title: Runtime Modes — Deep Explainer
since: 1.0.0
---

# Runtime Modes

## 1. Overview

Keylatch supports four runtime modes that control how credentials travel from the encrypted vault to the subprocess that needs them. Multiple modes exist because different contexts have different threat models: a local development script, an LLM agent session, and a CI pipeline each require different guarantees.

The trust hierarchy from highest to lowest isolation:

```
gateway_typed       (strongest isolation — gateway mediates all access)
gateway_sdk         (SDK-compatible proxy via gateway)
direct_brokered     (ephemeral broker tokens — no gateway required)
gateway_proxy       (MITM proxy rewriting Authorization headers)
```

All four modes are permitted in LLM sessions. Raw credential values are never returned to the agent process in any mode. `keylatch get` is always blocked in LLM sessions (exit 2, SecurityBlock).

---

## 2. Mode-by-mode reference

### `gateway_typed`

**What it does:** Routes credential injection through the local Keylatch gateway (`127.0.0.1:7878`). The subprocess receives a short-lived Keylatch session token and a gateway URL — not the raw provider key. The gateway validates actor, capability, and TTL, then forwards the request to the upstream provider with the real credential injected internally.

**When to use:** Default for LLM agent workflows. Provides the strongest isolation: the raw key never reaches the agent process environment.

**Required:** Gateway must be running (`keylatch gateway up`).

**Security invariants:**
- Raw credential value never enters the subprocess environment.
- Every request is audited with actor + capability + TTL.
- The gateway enforces the `authBlockerMiddleware`, `hostOverrideBlockerMiddleware`, and `SSRFGate` on all proxy routes.
- Session tokens expire; unlimited-use tokens (`--max-uses=0`) are rejected in LLM sessions.

**Receipt shape:**
```json
{
  "mode": "gateway_typed",
  "provider": "openrouter",
  "actor": "claude-code",
  "token_id": "tok_abc123",
  "ttl_seconds": 3600,
  "exit_code": 0
}
```

---

### `gateway_sdk`

**What it does:** Routes execution through the gateway using an OpenAI-compatible SDK proxy. The subprocess points its SDK base URL at the gateway; the gateway rewrites outbound requests with the real credential. Compatible with any SDK that accepts a configurable `baseURL`.

**When to use:** LLM agent workflows that use an OpenAI-compatible SDK (e.g. `openai` npm package, LangChain). Preferred over `gateway_proxy` for SDK clients because it does not require local CA installation.

**Required:** Gateway must be running.

**Security invariants:** Same as `gateway_typed`. Raw key never in subprocess environment.

**Receipt shape:** Same structure as `gateway_typed`, with `"mode": "gateway_sdk"`.

---

### `direct_brokered`

**What it does:** Exchanges credentials via a broker strategy that issues ephemeral tokens. The subprocess receives a short-lived token that can be exchanged for scoped access — it does not receive the raw API key. No gateway required.

**When to use:** Offline or low-latency scenarios where running the gateway is not practical, but direct key injection is still unacceptable.

**Required:** Nothing external. The broker runs in-process.

**Security invariants:**
- Ephemeral tokens expire on first use or by TTL.
- Raw credential value is not injected into subprocess environment.
- Audit log records token issuance and exchange.

**Receipt shape:**
```json
{
  "mode": "direct_brokered",
  "provider": "openrouter",
  "token_id": "brk_xyz789",
  "ttl_seconds": 300,
  "exit_code": 0
}
```

---

### `gateway_proxy`

**What it does:** Starts a local MITM proxy that intercepts HTTPS traffic and rewrites `Authorization` headers with the real credential before forwarding. The subprocess's HTTP client is pointed at the proxy via `HTTPS_PROXY`.

**When to use:** Processes that cannot accept a custom base URL (e.g. binary tools that hard-code the API endpoint). Requires local CA trust installation so the proxy can decrypt TLS.

**Required:** Gateway running; local CA trusted in the system store.

**Security invariants:**
- Raw credential value is not in subprocess environment.
- `SSRFGate` blocks non-allowlisted upstream destinations.
- CA private key is local-only, never transmitted.

**Receipt shape:**
```json
{
  "mode": "gateway_proxy",
  "provider": "openrouter",
  "proxy_addr": "127.0.0.1:7879",
  "exit_code": 0
}
```

---

## 3. LLM session restrictions

When Keylatch detects an active LLM session (via `CLAUDE_CODE`, `CODEX_ENV`, `CREDENTIALS_LLM_SESSION`, `CURSOR_SESSION`, `AIDER_SESSION`, `GEMINI_SESSION`, or `OPENCODE_SESSION` environment signals), it enforces the following policy:

| Mode | No LLM session | LLM session |
|------|:--------------:|:-----------:|
| `gateway_typed` | allowed | allowed |
| `gateway_sdk` | allowed | allowed |
| `direct_brokered` | allowed | allowed |
| `gateway_proxy` | allowed | allowed |

**What gets blocked vs allowed:**

- `keylatch get` — always blocked in LLM sessions (exit 2, SecurityBlock), regardless of mode
- `keylatch run` — allowed for all four modes in LLM sessions
- `keylatch ui` — scope locked to `status-only` (read-only); cannot approve/deny from UI in session
- `keylatch gateway token create --max-uses=0` — rejected; unlimited tokens are blocked in sessions

**How the guard detects LLM sessions:**

The guard calls `llmcontext.IsLLMSession(env)`, which checks for any of:
- `CLAUDE_CODE` set (any non-empty value)
- `CODEX_ENV` set
- `CREDENTIALS_LLM_SESSION=1`
- `CURSOR_SESSION` set
- `AIDER_SESSION` set
- `GEMINI_SESSION` set
- `OPENCODE_SESSION` set

Detection is conservative: any of these signals triggers full session restrictions.

---

## 4. Mode selection guide

Use this decision table to choose the right mode:

```
Am I in an LLM agent session?
  Yes → Does the provider template list gateway_typed or gateway_sdk?
          Yes → use gateway_typed (default) or gateway_sdk for OpenAI-compat SDKs
          No  → use direct_brokered

  No → Do I want the strongest isolation anyway?
         Yes → gateway_typed or gateway_sdk
         No  → Is the gateway running?
                 Yes → gateway_typed
                 No  → direct_brokered (no gateway needed)
```

Quick reference:

| I want... | Use mode |
|-----------|----------|
| Best isolation for AI agent | `gateway_typed` |
| OpenAI SDK compatibility | `gateway_sdk` |
| Offline, no gateway, reasonable isolation | `direct_brokered` |
| Binary tool that hard-codes endpoint | `gateway_proxy` |
