---
title: Telemetry
since: 1.0.0
---

# Telemetry

Keylatch optionally emits anonymous usage telemetry to help improve the product.
Telemetry is **opt-in by design** — it is only active when the operating mode is
`telemetry` or when `custom` mode explicitly enables it
(`custom.telemetry_enabled: true`).

## V1 Schema

All telemetry events share a common base envelope followed by event-specific fields.

### Base Envelope (all events)

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | string | Identifies the event (e.g. `cli_invoked`, `gateway_started`) |
| `install_id` | string | Stable, randomly generated 32-char hex identifier stored in `~/.keylatch/install_id`. Created on first run. Identifies an installation, not a user. |
| `version` | string | Keylatch version string (e.g. `1.2.3`) |
| `os` | string | Operating system name (`linux`, `darwin`, `windows`) |
| `arch` | string | CPU architecture (`amd64`, `arm64`) |
| `timestamp` | string (RFC 3339) | UTC timestamp of the event |

### `cli_invoked`

Emitted once per CLI invocation, after the command completes.

| Field | Type | Description |
|-------|------|-------------|
| `command` | string | Cobra command name (e.g. `run`, `doctor`) — never user arguments |
| `subcommand` | string | Subcommand name if applicable, or empty string |
| `exit_code` | integer | Process exit code |
| `duration_ms` | integer | Wall-clock duration of the invocation in milliseconds |

### `gateway_started`

Emitted when the keylatch gateway daemon starts successfully.

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | Provider name (e.g. `aws`, `gcp`) — never a credential value |
| `runtime` | string | Gateway runtime: `local`, `docker`, or `hosted` |

### `connection_enrolled`

Emitted when a new connection is enrolled.

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | Provider name (e.g. `openai`, `anthropic`) |
| `storage_mode` | string | `direct` (credential stored locally) or `reference` (external store pointer) |

### `doctor_run`

Emitted after `keylatch doctor` completes.

| Field | Type | Description |
|-------|------|-------------|
| `category` | string | Check category (e.g. `backend`, `tls`, `auth`) |
| `result` | string | Overall result: `ok`, `warn`, `fail`, or `skip` |
| `failed_check_names` | array of string | Names of failed checks — only present when `result` is `fail`. Contains check identifiers, never user data. Omitted when empty. |

---

## What Telemetry Does NOT Collect

Keylatch telemetry is designed to be non-identifying and non-sensitive. The
following information is **never** included in any emitted event:

- **Connection names** — the names you give to your enrolled connections
- **Credentials** — API keys, tokens, passwords, or any secret values
- **File paths** — vault paths, config paths, or any filesystem locations
- **Command arguments** — values passed to CLI flags or positional arguments
- **Environment variable values** — only presence/absence of specific variables (and only anonymised)
- **IP addresses or network identifiers**
- **User accounts or email addresses**

The `install_id` is a random identifier that is not linked to any account and
cannot be used to identify an individual. It is stored only on your machine.

---

## Kill-Switch

To disable all telemetry regardless of operating mode or configuration:

```sh
export KEYLATCH_TELEMETRY_DISABLE=1
```

This environment variable takes precedence over every other telemetry setting,
including the `mode` field in `config.json`. Set it in your shell profile to
permanently opt out.

You can also verify which mode is active:

```sh
keylatch config show | grep mode
```

---

## Enabling Telemetry

Telemetry is inactive in `standard` (default) mode. To enable it:

**Option 1 — telemetry mode:**

```sh
keylatch config set mode telemetry
```

**Option 2 — custom mode:**

```json
{
  "mode": "custom",
  "custom": {
    "telemetry_enabled": true
  }
}
```

---

## Remote Endpoint

Events are sent via HTTPS POST to `https://telemetry.keylatch.dev/v1/events`.
This endpoint can be overridden with `KEYLATCH_TELEMETRY_URL` (used by CI canary
scans and local testing — not intended for end-user use).

The remote sink uses a 3-attempt retry policy with exponential backoff
(wait 5 s after attempt 1, wait 30 s after attempt 2, then give up silently).
All telemetry failures are swallowed — a broken endpoint never surfaces an error
to the user or blocks the CLI from exiting.
