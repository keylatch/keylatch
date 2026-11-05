---
title: Runtime Modes — Deep Explainer
since: 1.0.0
---

# Runtime Modes

## 1. Overview

Keylatch supports three runtime modes (plus the experimental `gateway_proxy`) that control how credentials travel from the encrypted vault to the subprocess that needs them. Multiple modes exist because different contexts have different threat models: a local development script, an LLM agent session, and a CI pipeline each require different guarantees.

The trust hierarchy from highest to lowest isolation:

```
gateway_typed       (strongest isolation — gateway mediates all access)
gateway_sdk         (SDK-compatible proxy via gateway)
minted              (scoped credential minted per command — no gateway required)
gateway_proxy       (MITM proxy rewriting Authorization headers)
```

The gateway modes are permitted in LLM sessions. `minted` hands the command a real, scoped credential, so a connection's mint policy refuses agent sessions. Raw stored credential values are never returned to the agent process in any mode. `keylatch get` is always blocked in LLM sessions (exit 2, SecurityBlock).

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

### `minted`

**What it does:** Mints a short-lived credential limited to one scope with the template's mint strategy, gives it to the subprocess in a clean environment and revokes it when the subprocess exits. It replaces `direct_brokered`, which exits 5 and names `minted`. No gateway required.

**When to use:** Tools that need a real provider credential in their environment (`gh`, `aws`, `terraform`) where that credential can be limited: a GitHub App installation token for one repository, or AWS STS credentials limited by a session policy. See [Runtime modes](../runtime-modes.md#minted-credentials).

**Required:** A connection whose template declares `minted_fields` and an operator `mint` policy for it.

**Security invariants:**
- The stored root credential is never read for the command; a template with only static fields refuses `minted`.
- Agent sessions are refused.
- The environment is an allowlist, not the parent environment.
- Every mint writes an audit event without the credential, and the credential is revoked on exit.

**Receipt shape:**
```json
{
  "mode": "minted",
  "provider": "github-app",
  "credential_shape": "provider_ephemeral",
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

When Keylatch detects an active LLM session (via `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT`, `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED`, `CURSOR_AGENT`, `CURSOR_TRACE_ID`, `GEMINI_CLI`, `OPENCODE`, or the manual `CREDENTIALS_LLM_SESSION` flag), it enforces the following policy:

| Mode | No LLM session | LLM session |
|------|:--------------:|:-----------:|
| `gateway_typed` | allowed | allowed |
| `gateway_sdk` | allowed | allowed |
| `minted` | allowed | refused by the mint policy |
| `gateway_proxy` | allowed | allowed |

**What gets blocked vs allowed:**

- `keylatch get` — always blocked in LLM sessions (exit 2, SecurityBlock), regardless of mode
- `keylatch run` — allowed for all four modes in LLM sessions
- `keylatch ui` — scope locked to `status-only` (read-only); cannot approve/deny from UI in session
- `keylatch gateway token create --max-uses=0` — rejected; unlimited tokens are blocked in sessions

**How the guard detects LLM sessions:**

The guard calls `llmcontext.IsLLMSession(env)`, which checks for any of:
- `CLAUDECODE` or `CLAUDE_CODE_ENTRYPOINT` (Claude Code)
- `CODEX_SANDBOX` or `CODEX_SANDBOX_NETWORK_DISABLED` (Codex CLI)
- `GEMINI_CLI` (Gemini CLI)
- `OPENCODE` (OpenCode)
- `CURSOR_AGENT` or `CURSOR_TRACE_ID` (Cursor)
- `CREDENTIALS_LLM_SESSION` set to anything but `0` (manual flag)
- legacy aliases `CLAUDE_CODE`, `CODEX_ENV`, `CURSOR_SESSION`, `AIDER_SESSION`, `GEMINI_SESSION`, `OPENCODE_SESSION`

Any non-empty value triggers full session restrictions. The agent controls these variables, so detection is a convenience, not a security boundary.

---

## 4. Mode selection guide

Use this decision table to choose the right mode:

```
Am I in an LLM agent session?
  Yes → Does the provider template list gateway_typed or gateway_sdk?
          Yes → use gateway_typed (default) or gateway_sdk for OpenAI-compat SDKs
          No  → ask the owner for a placeholder session (keylatch run --tier D3)

  No → Do I want the strongest isolation anyway?
         Yes → gateway_typed or gateway_sdk
         No  → Is the gateway running?
                 Yes → gateway_typed
                 No  → minted, if the template mints (no gateway needed)
```

Quick reference:

| I want... | Use mode |
|-----------|----------|
| Best isolation for AI agent | `gateway_typed` |
| OpenAI SDK compatibility | `gateway_sdk` |
| A real provider credential, limited to one scope and revoked on exit | `minted` |
| Binary tool that hard-codes endpoint | `gateway_proxy` |
