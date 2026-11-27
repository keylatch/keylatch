# Keylatch CONNECT Proxy

The Keylatch CONNECT proxy is an HTTP CONNECT-based interception proxy that sits between your tool and the internet, injecting credentials into outbound HTTPS connections to provider APIs.

## How it works

When an LLM tool (or any HTTP client) makes a CONNECT request through the proxy, Keylatch intercepts the TLS tunnel and injects the appropriate API credentials before forwarding the request to the upstream provider. The proxy operates transparently from the tool's perspective.

Because the proxy terminates TLS, it must present a locally-trusted CA certificate to the client. **The client must trust the Keylatch CA before using the proxy.** `keylatch run` hands the CA to the child through the CA bundle variables; trust it system-wide only for tools that ignore them.

## Choosing between proxy and gateway modes

| Mode | When to use |
|---|---|
| `gateway_typed` | Default. Gateway speaks the provider's typed API. Best isolation. |
| `gateway_sdk` | Gateway proxies to the provider SDK running inside a sandboxed sub-process. |
| `gateway_proxy` | Use when the tool only supports HTTP_PROXY / HTTPS_PROXY environment variables and cannot be adapted to a gateway URL. |

Use `keylatch proxy` (this document) only when `gateway_typed` or `gateway_sdk` are not suitable — for example, when a tool does not accept a gateway URL but does respect `HTTP_PROXY` / `HTTPS_PROXY`.

## Independent lifecycle

The proxy and gateway have **independent lifecycles**:

- `keylatch gateway down` does NOT stop the proxy.
- `keylatch proxy down` does NOT stop the gateway.
- You can run the proxy with or without the gateway.

## Lifecycle commands

### Start the proxy

```
keylatch proxy up [--port N] [--detach]
```

- Default port: **8888**
- `--detach`: start the proxy as a background process. The parent waits up to 3 seconds for the PID file to appear before returning.
- Refuses to start if the proxy is already running on that port.
- Cleans up stale PID files automatically.
- Writes a PID file to `~/.keylatch/proxy.pid` (or the path derived from `KEYLATCH_CONFIG_DIR`).

### Stop the proxy

```
keylatch proxy down
```

- Sends SIGTERM. Waits up to 5 seconds for a graceful exit. Sends SIGKILL if the process does not exit in time.
- If no PID file is found, exits 0 with "Proxy is not running."
- If a stale PID file is found (process is dead), removes it and exits 0.

### Check proxy status

```
keylatch proxy status [--json]
```

Three states:
- **running** — PID file exists and the process is alive.
- **not-running** — no PID file.
- **stale** — PID file exists but the process is dead (does not auto-clean; run `proxy down` to clean).

JSON output shape:

```json
{
  "running": true,
  "pid": 12345,
  "address": "127.0.0.1:8888",
  "uptimeSeconds": 3721
}
```

When not running, `pid` and `uptimeSeconds` are `null` and `address` is omitted.

## Gateway and proxy lifecycles

The gateway and the proxy start and stop independently. `keylatch gateway down` does **not** stop the proxy; stop it with `keylatch proxy down`.

## CA trust requirement

The proxy must present a CA certificate the client trusts to intercept TLS connections. Without it, clients receive a certificate error when connecting through the proxy.

## PID file location

The proxy PID file is stored at:

```
~/.keylatch/proxy.pid
```

Override the config directory with `KEYLATCH_CONFIG_DIR`.

## Audit events

The proxy emits the following audit events:

| Event | When |
|---|---|
| `proxy.started` | `proxy up` succeeds (foreground mode) |
| `proxy.stopped` | `proxy down` completes |

The `proxy.stopped` event includes a `reason` field: `sigterm`, `sigkill`, or `already-dead`.
