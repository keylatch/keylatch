# `keylatch doctor --json`

`keylatch doctor --json` prints one JSON document that validates against
[`schemas/doctor.schema.json`](../../schemas/doctor.schema.json). The exit code is the same as in
text mode: `0` all passed, `1` warnings only, `2` at least one failure.

## Top-level fields

| Field | Meaning |
|-------|---------|
| `_schema` | Always `"v1"`. |
| `exit` | The exit code the command returns. |
| `summary` | Counts of checks: `ok`, `warn`, `fail`, `skipped`. |
| `agent_session` | Whether the process looks like an agent session, see below. |
| `checks` | Every check, passing ones included. |
| `sections` | One summary per section. |
| `overall_ok`, `has_warnings` | The same verdict the exit code carries. |
| `operating_mode`, `version`, `platform`, `cipher_suite`, `fips_build` | Build and configuration facts. |

## `agent_session`

```json
{ "detected": true, "signals": ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"], "harness": "claude-code" }
```

`signals` lists what fired: environment variable names, `ancestry:<harness>` when a parent process
is a known harness, or `ticket` for a session ticket. `harness` is empty when the signals do not
point to one harness.

## One failure per root cause

When a check fails because something it depends on is broken, it is not reported as a second
failure. It is reported with `"skipped": true` and counted under `summary.skipped`. A machine where
Keylatch was never set up shows one failure for the missing setup, not one per file that is
missing as a result.

| Root cause | Check that reports it | Checks skipped when it fails |
|------------|----------------------|------------------------------|
| Not set up | `bootstrap.keyring` | `bootstrap.config`, `paths.*`, `audit.writable`, `audit.chain`, `backend.file`, `backend.kek` |
| No guard hook | `guard.installed` | `guard.current`, `guard.matcher` |

## Checks added for agent safety

| Check | Fails or warns when |
|-------|--------------------|
| `backend.kek` | The key-encryption key sits in a plaintext file. |
| `policy.default_deny` | There is no policy file, or the policy is not default-deny. |
| `guard.installed` | A Claude Code configuration directory has no Keylatch guard hook. |
| `guard.current` | The installed guard script is older than the one this build ships. |
| `guard.matcher` | The guard hook covers only some tools. |
| `env.backend_credentials` | Backend credentials are exported to the process (warning, names only). |
| `audit.chain` | The audit log's hash chain does not verify. |
| `backend.tier` | The selected backend is community or deprecated (warning), or unknown. |
| `backend.bw_session_file` | A cached Bitwarden session file is on disk (warning). |
| `mode.deployment` | Reports the in-user deployment mode. |

Every `fix` is a command to run. None names a path inside the repository.
