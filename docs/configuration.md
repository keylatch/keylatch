---
title: Configuration
description: Full reference for config.json configuration keys.
---

# Configuration

Keylatch reads its configuration from `~/.keylatch/config.json` (or the path
set by `KEYLATCH_CONFIG`). All keys are optional — Keylatch applies safe
defaults when a key is absent.

## Key reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `backend` | string | `file` | Credential storage backend. One of `file`, `keychain`, `op`, `bw`, `protonpass`, `keeper`, `lastpass`, `vault`, `awssm`, `opconnect`, `gcpsm`, `azurekv`, `doppler`, `infisical`. |
| `mode` | string | `standard` | **Operating mode** — controls telemetry, canary injection, and experimental gates. One of `standard`, `telemetry`, `canary`, `custom`. See [Operating Modes](./operating-modes.md) for the full reference. |
| `audit.enabled` | bool | `true` | Whether to write a tamper-evident audit log. Disabling is not recommended in production. |
| `audit.retention_days` | int | `30` | Number of days to retain rotated audit log files. Valid range: 1–3650. Rotated files older than this threshold are deleted by the retention sweep. |
| `audit.sweep_interval_hours` | int | `24` | How often (in hours) the retention sweep runs. Minimum: 1. The sweep is run as a background goroutine by `keylatchd`. |
| `gateway.endpoint` | string | `http://127.0.0.1:7878` | Full URL of the local gateway server. Override if you run the gateway on a non-default port. |
| `gateway.mode` | string | `local` | Gateway mode. One of `local`, `docker`, `hosted`, `off`. |

## Example configuration

```json
{
  "version": 1,
  "backend": "keychain",
  "audit": {
    "enabled": true,
    "retention_days": 90,
    "sweep_interval_hours": 24
  },
  "gateway": {
    "endpoint": "http://127.0.0.1:7878",
    "mode": "local"
  }
}
```

## Environment variable overrides

Selected configuration values can be overridden with environment variables:

| Config key | Environment variable |
|------------|---------------------|
| `backend` | `KEYLATCH_BACKEND` |
| `audit.enabled` | `KEYLATCH_AUDIT__ENABLED` |
| `gateway.endpoint` | `KEYLATCH_GATEWAY__ENDPOINT` |

The gateway listen address (for `keylatch gateway up`) can also be overridden independently:

```bash
export KEYLATCH_GATEWAY_ADDR=127.0.0.1:7891
keylatch gateway up
```

## Config commands

```bash
# List all configuration values
keylatch config list

# Get a specific key
keylatch config get backend

# Set a key
keylatch config set backend file
keylatch config set backend keychain
```

Credential values are rejected by `config set` — use `keylatch set` for credentials.
Numeric fields (e.g. `audit.max_size_bytes`) cannot be set via `config set`; edit `config.json` directly.
