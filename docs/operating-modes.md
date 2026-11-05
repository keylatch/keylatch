---
title: Operating Modes
description: How Keylatch's three operating modes control canary injection and experimental gates.
---

# Operating Modes

Keylatch has three operating modes that decide which optional subsystems are active during a
session. A mode replaces ad-hoc boolean flags with one auditable configuration value.

## Mode comparison

| Feature | standard | canary | custom |
|---------|----------|--------|--------|
| Canary injection | off | **on** | configurable |
| Experimental gates | off | off | configurable |

## Per-mode walkthrough

### standard (default)

All optional subsystems are off. No canary tokens are injected. This is the safest choice for
production work.

```sh
keylatch run --mode standard anthropic -- env
```

### canary

A synthetic canary token is injected into the child process environment next to the gateway token.
The token follows the pattern:

```
klc-canary-<provider>-<random16hex>
```

For example `klc-canary-anthropic-a3f5c2e1d8b7a904`. To find one in a log or output file:

```sh
grep -E 'klc-canary-[a-z0-9_]+-[0-9a-f]{16}' /path/to/output.log
```

The variable injected is `KEYLATCH_CANARY_<PROVIDER>` (for example `KEYLATCH_CANARY_ANTHROPIC`).
The canary value is never logged; only metadata (provider, session ID) appears in the audit log, as
the event `canary.injected`.

```sh
keylatch run --mode canary anthropic -- env | grep KEYLATCH_CANARY
```

To persist the choice:

```sh
keylatch config set mode canary
```

### custom

Individual flags are set independently. Edit `config.json` in the Keylatch config directory:

```json
{
  "mode": "custom",
  "custom": {
    "canary_injection_enabled": false,
    "experimental_gated": true
  }
}
```

## Selection precedence

The mode is resolved in this order, highest priority first:

1. `--mode <name>` on `keylatch run`
2. the `KEYLATCH_MODE` environment variable
3. the `mode` key in `config.json`
4. the default, **standard**

```sh
# The flag overrides everything
keylatch run --mode canary anthropic -- env

# The environment variable overrides the config file
KEYLATCH_MODE=canary keylatch run anthropic -- env
```

## Doctor check

`keylatch doctor` includes a `mode.operating` check that reports the effective settings:

```
[ ok ] mode.operating: active=canary, canary_injection=on, experimental_gated=off
```

In JSON mode (`keylatch doctor --json`) the resolved mode appears as `operating_mode` at the top
level; see [doctor JSON](cli/doctor-json.md).
