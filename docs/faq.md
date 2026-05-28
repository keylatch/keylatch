---
title: FAQ
since: 0.1.0
---

# FAQ

Answers to common questions in the first hour of using Keylatch.

---

**1. How is this different from just using a `.env` file?**

A `.env` file stores credentials in plaintext on disk, and any process — including LLM agents — can read them directly. Keylatch encrypts credentials at rest, enforces per-operation access control, detects active LLM sessions and blocks direct value extraction, and maintains a tamper-evident audit log of every read and injection. You get a verifiable chain of custody without ever exposing a raw key to the session.

---

**2. Does Keylatch send my credentials anywhere?**

No. Keylatch is a local process. In gateway modes, the gateway runs on `127.0.0.1:7878` and forwards requests to the provider on your behalf — but your raw API key never leaves your machine through Keylatch itself. The gateway receives only a short-lived session token from the agent, not the credential. See [Security](security.md) for the full model.

---

**3. What's the difference between the four runtime modes?**

`gateway_typed` (default) routes execution through the local Keylatch gateway. The agent process receives a short-lived token and a gateway URL — never the raw provider key. `gateway_sdk` does the same using an OpenAI-compatible SDK proxy. `direct_brokered` issues ephemeral broker tokens without requiring the gateway. `gateway_proxy` intercepts HTTPS traffic via a local MITM proxy. All four modes are safe for LLM sessions. See [Runtime Modes](architecture/modes.md) for the full comparison.

---

**4. I ran `keylatch run` and got "gateway is not running" — what do I do?**

Start the gateway first:

```bash
keylatch gateway up --detach
```

Then retry your `keylatch run` command. If you do not want to run the gateway, use a mode that does not require it:

```bash
keylatch run openrouter --runtime direct_brokered -- your-command
```

Check the current gateway state with `keylatch gateway status`.

---

**5. How do I use Keylatch with Claude Code?**

Run `keylatch setup agent` (or `keylatch agent setup` via the daemon API) to write a Claude Code settings snippet that registers the Keylatch MCP server and sets the required environment variables. After setup, Claude Code passes requests through Keylatch's gateway rather than reading credentials from the environment directly. The `contrib/agent-guards/claude-code/` directory also contains a hook script that blocks direct vault access attempts.

---

**6. Does this work in CI / headless environments?**

Yes, with the right backend. The `file` backend works everywhere with no UI. For 1Password in CI, set `OP_SERVICE_ACCOUNT_TOKEN` and `KEYLATCH_BACKEND=op` — no interactive unlock required. For Bitwarden, set `BW_SESSION` from `bw unlock --raw`. The `file` backend is the simplest headless option. See [Backends](backends/index.md) for CI-specific notes per backend.

---

**7. Can I use Keylatch with multiple provider keys at once?**

Yes. Each `keylatch connect` call stores a separate credential under a unique path. You can have multiple providers connected simultaneously:

```bash
# Interactive (recommended):
keylatch connect openrouter
keylatch connect anthropic
keylatch connect stripe

# Or via stdin (CI-safe):
printf '%s' "$OPENROUTER_API_KEY" | keylatch connect openrouter -f api_key=@-
printf '%s' "$ANTHROPIC_API_KEY"  | keylatch connect anthropic -f api_key=@-
printf '%s' "$STRIPE_SECRET_KEY"  | keylatch connect stripe -f secret_key=@-
```

`keylatch run` takes the connection name as its first argument, so each invocation uses exactly the credential you specify. Use `keylatch list` to see all stored connections.

---

**8. What happens if the gateway crashes mid-run?**

The subprocess that `keylatch run` already started continues to run — it received its environment variables at launch and does not hold a live connection to the gateway. The gateway is only needed at the moment `keylatch run` starts, to mint the session token and inject credentials. A crash after launch does not affect the running subprocess. The audit log records the injection event regardless of gateway liveness after the fact.

---

**9. Where are my credentials actually stored?**

That depends on your configured backend:

- **file** — encrypted blobs in `~/.keylatch/vault/` (XChaCha20-Poly1305, Argon2id key derivation)
- **keychain** — macOS Keychain via the Security framework (`login.keychain-db`)
- **op** — your 1Password vault (Keylatch writes items tagged `Keylatch`)
- **bw** — your Bitwarden / Vaultwarden vault

Run `keylatch doctor --json` to see the active backend and vault path. See [Backends](backends/index.md) for full detail.

---

**10. How do I rotate a credential?**

Run `keylatch connect` again with the new value — it overwrites the existing entry and increments the version counter:

```bash
# Interactive (recommended):
keylatch connect openrouter

# Or via stdin:
printf '%s' "$NEW_OPENROUTER_KEY" | keylatch connect openrouter -f api_key=@-
```

To inspect version history: `keylatch versions openrouter api_key`. To roll back: `keylatch rollback openrouter api_key <version>`. The audit log records all write and rotation events without storing the credential values.
