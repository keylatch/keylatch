# Keylatch Guard — Windsurf

Windsurf does not currently expose a hook API for tool interception.

## Recommended Alternative

Use Keylatch in gateway mode, which intercepts all outbound credential requests at the network level regardless of agent:

```bash
keylatch proxy start --port 8080
# Point Windsurf's network proxy setting to http://localhost:8080
```

See: https://keylatch.dev/integrations/windsurf

## Manual Guard (Future)

`block-keylatch-exfiltration.sh` is provided for future hook API integration when Windsurf exposes a PreToolUse hook mechanism. For manual guard instructions see keylatch.dev/integrations/windsurf.

## Install

```bash
keylatch install-guard windsurf
```

This prints the above guidance and recommends gateway mode.
