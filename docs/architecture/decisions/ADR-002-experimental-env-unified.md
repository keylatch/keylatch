# ADR-002: Unify experimental gating under KEYLATCH_EXPERIMENTAL

## Status: Accepted

## Context

Two env vars gate experimental features: `KEYLATCH_EXPERIMENTAL` gates the CLI `experimental`
subcommand tree and the UI `/experimental` endpoint; `KEYLATCH_EXPERIMENTAL_BACKENDS` gates the
NordPass backend stub. The 1.0.0 spec requires a single opt-in contract — shipping two separate
knobs confuses users and makes the feature surface harder to document.

EPIC-17 added `EffectiveSettings.ExperimentalGated bool` to `internal/runtime/mode.go`, allowing
custom mode config to persist the preference so users do not need the env var every session.

## Decision

Unify under `KEYLATCH_EXPERIMENTAL=1`. `KEYLATCH_EXPERIMENTAL_BACKENDS` is deprecated and ignored.

The gate resolver in `internal/cli/experimental.go` is promoted to an exported function
`IsExperimentalEnabled(settings runtime.EffectiveSettings) bool` that checks either the env var or
the `ExperimentalGated` flag from the resolved settings, whichever is true:

```go
func IsExperimentalEnabled(settings runtime.EffectiveSettings) bool {
    return os.Getenv("KEYLATCH_EXPERIMENTAL") == "1" || settings.ExperimentalGated
}
```

The env var takes precedence as a per-process override; `ExperimentalGated` covers the persisted
custom-mode preference.

## Consequences

- NordPass backend now requires `KEYLATCH_EXPERIMENTAL=1` (not `KEYLATCH_EXPERIMENTAL_BACKENDS=1`)
- Users with `KEYLATCH_EXPERIMENTAL_BACKENDS=1` in their shell must update to `KEYLATCH_EXPERIMENTAL=1`
- Custom mode (`custom.experimental_gated = true` in config) is equivalent to the env var — users
  do not need to set the env var every session when using custom mode
- `KEYLATCH_EXPERIMENTAL_BACKENDS` is removed from `docs/cli/environment.md` (marked deprecated)
- All experimental feature documentation is consolidated in `docs/experimental.md`

## Alternatives considered

- **Keep both vars**: rejected — two contracts confuse users and require double documentation
- **Add a third var `KEYLATCH_EXPERIMENTAL_ALL`**: rejected — unnecessary indirection
- **Invert precedence (settings > env)**:  rejected — env var overrides are a conventional escape
  hatch; process-level flag must win over persisted config
