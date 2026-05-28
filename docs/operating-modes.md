---
title: Operating Modes
description: How keylatch's four operating modes control telemetry, canary injection, and experimental gates.
---

# Operating Modes

KeyLatch supports four first-class operating modes that control which subsystems are active during a session. Operating modes replace ad-hoc boolean flags with a single, auditable configuration value.

## Mode comparison matrix

| Feature | standard | telemetry | canary | custom |
|---------|----------|-----------|--------|--------|
| Telemetry | off | **on** | off | configurable |
| Canary injection | off | off | **on** | configurable |
| Experimental gates | off | off | off | configurable |

## Per-mode walkthrough

### standard (default)

All optional subsystems are disabled. No telemetry is collected; no canary tokens are injected. This is the safest choice for production workloads.

```sh
keylatch run --mode standard anthropic -- env
```

### telemetry

Anonymous usage metrics are sent to the KeyLatch telemetry sink. Metrics contain no secret values — only event counts and timing data. Canary injection remains off.

```sh
keylatch run --mode telemetry anthropic -- env
```

To persist this choice:

```sh
keylatch config set mode telemetry
```

### canary

A synthetic canary token is injected into the child process environment alongside the gateway token. The token follows the pattern:

```
klc-canary-<provider>-<random16hex>
```

Example: `klc-canary-anthropic-a3f5c2e1d8b7a904`

To detect a canary token in a log or output file:

```sh
grep -E 'klc-canary-[a-z0-9_]+-[0-9a-f]{16}' /path/to/output.log
```

The environment variable injected is `KEYLATCH_CANARY_<PROVIDER>` (e.g. `KEYLATCH_CANARY_ANTHROPIC`). The canary value is never logged — only metadata (provider, session_id) appears in the audit log as action `canary.injected`.

```sh
keylatch run --mode canary anthropic -- env | grep KEYLATCH_CANARY
```

### custom

Individual feature flags can be toggled independently. Edit `~/.keylatch/config.json` directly:

```json
{
  "mode": "custom",
  "custom": {
    "telemetry_enabled": true,
    "canary_injection_enabled": false,
    "experimental_gated": true
  }
}
```

## Selection precedence

Operating mode is resolved in this order (highest priority first):

1. `--mode <name>` flag on `keylatch run`
2. `KEYLATCH_MODE` environment variable
3. `mode` key in `~/.keylatch/config.json`
4. Default: **standard**

```sh
# Flag overrides everything
keylatch run --mode canary anthropic -- env

# Env var overrides config
KEYLATCH_MODE=telemetry keylatch run anthropic -- env

# Persist via config
keylatch config set mode canary
```

## Canary mode: token pattern and detection

Canary tokens are synthetic credentials injected in canary mode to detect accidental key exfiltration.

**Pattern**: `klc-canary-<provider>-<16 hex chars>`

**Environment variable**: `KEYLATCH_CANARY_<PROVIDER_UPPER>`

**Detection**:

```sh
# Grep for any canary token in a file
grep -E 'klc-canary-[a-z0-9_]+-[0-9a-f]{16}' <file>

# Confirm ANTHROPIC canary was injected in a live session
keylatch run --mode canary anthropic -- env | grep KEYLATCH_CANARY_ANTHROPIC
```

**Audit**: When a canary token is injected, the audit log records action `canary.injected` with fields `provider` and `session_id`. The token value is never written to the audit log.

## Doctor check

`keylatch doctor` includes a `mode.operating` check that reports the current effective settings:

```
[ ok ] mode.operating: active=canary, telemetry=off, canary_injection=on, experimental_gated=off
```

In JSON mode (`keylatch doctor --json`), the resolved mode name appears as `"operating_mode"` at the top level of the output document.
