---
title: Process Isolation
description: How Keylatch isolates subprocess access to credentials.
---

# Process Isolation

Keylatch v1.0.0 achieves subprocess isolation through gateway-based runtime modes rather than OS-level sandboxing. Credentials are never injected into the subprocess environment directly; instead, agent processes receive short-lived session tokens.

## Gateway-based isolation (v1.0.0)

All four v1.0.0 runtime modes keep the raw credential value inside the `keylatchd` process:

| Mode | How isolation works |
|------|---------------------|
| `gateway_typed` | Subprocess receives a scoped JWT; gateway forwards to upstream with real key injected server-side |
| `gateway_sdk` | Same as `gateway_typed` with an OpenAI-compatible base URL |
| `direct_brokered` | Subprocess receives an ephemeral exchange token; raw key is never injected |
| `gateway_proxy` | Subprocess sends requests through a local MITM proxy; proxy injects real key before forwarding |

In all modes, the subprocess never sees the raw provider API key.

## Recommended setup on all platforms

```bash
# Start the gateway
keylatch gateway up --detach

# Run with gateway_typed (default, strongest isolation)
keylatch run openrouter -- my-command
```

For processes that do not support custom base URLs or proxy settings, use `gateway_proxy`.

## Diagnosing mode availability

```bash
keylatch runtime doctor <provider>
```

Reports which modes are supported by the provider template and available given the current system state (gateway running, CA installed, etc.).
