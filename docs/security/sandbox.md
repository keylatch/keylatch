---
title: Process Isolation
description: How Keylatch isolates subprocess access to credentials.
---

# Process Isolation

Keylatch limits what a subprocess holds through gateway-based runtime modes rather than OS-level sandboxing. Credentials are not injected into the subprocess environment; agent processes receive short-lived session tokens. This runs as your user, so it is not a boundary against an agent that reads your files or processes directly.

## Gateway-based isolation

The three available runtime modes keep the raw credential value inside the `keylatchd` process:

| Mode | How isolation works |
|------|---------------------|
| `gateway_typed` | Subprocess receives a scoped JWT; gateway forwards to upstream with real key injected server-side |
| `gateway_sdk` | Same as `gateway_typed` with an OpenAI-compatible base URL |
| `minted` | Subprocess receives a credential minted for it and limited to one scope, revoked on exit; the stored key is never injected |

In all modes, the subprocess never receives the raw provider API key.

## Recommended setup on all platforms

```bash
# Start the gateway
keylatch gateway up --detach

# Run with gateway_typed (default, strongest isolation)
keylatch run openrouter -- my-command
```

## Diagnosing mode availability

```bash
keylatch runtime doctor <provider>
```

Reports which modes the provider template supports and which are available given the current system state (gateway running, and so on).
