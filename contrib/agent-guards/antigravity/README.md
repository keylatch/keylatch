# Keylatch Guard — Antigravity

Google Antigravity does not currently expose a hook API for tool interception.

## Recommended Alternative

Run Keylatch in gateway mode, which intercepts all outbound credential requests at the network level regardless of agent:

```bash
keylatch proxy start --port 8080
# Point Antigravity's network proxy setting to http://localhost:8080
```

See: https://keylatch.dev/integrations/antigravity

## Install

```bash
keylatch install-guard antigravity
```

This prints the above guidance.
