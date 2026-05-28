---
title: Experimental Features
since: 1.0.0
---

# Experimental Features

Experimental features are opt-in and not covered by the stable API guarantee. They may change or
be removed without a minor-version bump. Features graduate to stable when they ship in a release
and the gating check is removed.

## Enabling experimental mode

Set the environment variable:

```sh
KEYLATCH_EXPERIMENTAL=1 keylatch <command>
```

Or persist it via custom mode config so you do not need the env var every session:

```yaml
# ~/.keylatch/config.yaml  (mode: custom)
custom:
  experimental_gated: true
```

Both methods are equivalent for CLI commands and backend gating. The env var takes precedence as
a per-process override.

> **Note**: The UI server's `/v1/config/experimental` endpoint responds to `KEYLATCH_EXPERIMENTAL=1`
> only and does not yet honor `custom.experimental_gated`. This is a known limitation. See the
> feature table below for details.

> **Deprecated**: `KEYLATCH_EXPERIMENTAL_BACKENDS=1` was previously used to gate the NordPass
> backend. It is now **ignored**. Update any shell profiles or CI scripts to use
> `KEYLATCH_EXPERIMENTAL=1` instead.

---

## Current experimental features

| Feature | Gate | Status | Notes |
|---------|------|--------|-------|
| NordPass backend stub | `KEYLATCH_EXPERIMENTAL=1` | Discovery-gated | All methods return `ErrUnavailable`; no official NordPass CLI/API contract confirmed yet |
| UI `/v1/config/experimental` endpoint | `KEYLATCH_EXPERIMENTAL=1` only | Active | Returns `{"experimental": true}` when `KEYLATCH_EXPERIMENTAL=1`. **Known limitation**: this endpoint reads the env var directly and does not consult `custom.experimental_gated`. Users relying solely on custom mode config will see `{"experimental": false}`. Setting `KEYLATCH_EXPERIMENTAL=1` alongside `custom.experimental_gated: true` works correctly. |
| Beta runtime modes | `KEYLATCH_EXPERIMENTAL=1` | Planned | Future additions will be listed here when they enter beta |

---

## Graduation policy

When an experimental feature ships as stable:

1. The gating check (`IsExperimentalEnabled`) is removed from the feature's code path.
2. A CHANGELOG entry states: `stabilized: <feature name>`.
3. The feature is removed from the table above.
4. The `docs/` page for the feature (if any) is updated to drop the experimental notice.

Features that are removed without graduating are marked **Dropped** in the CHANGELOG.

---

## Integration with custom mode (EPIC-17)

`EffectiveSettings.ExperimentalGated` is set to `true` when:

- `KEYLATCH_EXPERIMENTAL=1` is present in the process environment, **or**
- The resolved operating mode is `custom` and `custom.experimental_gated = true` in config.

Callers that need to check the gate should use:

```go
import "github.com/keylatch/keylatch/internal/cli"

if cli.IsExperimentalEnabled(settings) {
    // feature is active
}
```

Do **not** read `KEYLATCH_EXPERIMENTAL` directly — use `IsExperimentalEnabled` so the custom-mode
path is always respected.
