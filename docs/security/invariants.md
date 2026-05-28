# Security Invariants

Keylatch enforces five user-facing security properties at runtime:

| # | Invariant | What it means |
|---|-----------|---------------|
| 1 | Your secrets never touch agent memory | Credential values are never serialised into model context, MCP tool outputs, or agent logs. `keylatch run` injects into a subprocess environment only. |
| 2 | Every secret use is logged | Every read, write, decrypt, and policy-check is written to the append-only HMAC-chained audit log. |
| 3 | Revoking access is instant | Removing a grant or connection takes effect on the next request — no TTL propagation delay. |
| 4 | Approvals expire automatically | Gateway tokens and approval JWTs have mandatory TTLs. Unlimited-TTL tokens are rejected. |
| 5 | No secret leaves your machine without your say-so | Gateway mode routes requests through a local process that you control; the raw credential is never sent to a remote endpoint. |

## Cross-reference: internal IDs

The invariants above correspond to the following internal security requirements. The internal IDs appear only in this file and in the codebase — not on user-facing surfaces.

| Internal ID | Invariant # | User-facing description | Enforcing code / config |
|-------------|-------------|------------------------|------------------------|
| S-RM-1 | 1 | Secrets never touch agent memory | `internal/cli/guard.go` `GuardLLMSession`; `contrib/agent-guards/claude-code/block-keylatch-exfiltration.sh` |
| S-RM-3 | 2 | Every secret use is logged | `internal/audit/audit.go` `Logger.Log`; all action constants in `audit.go` |
| S-RM-6 | 3 | Revoking access is instant | `internal/grant/grant.go` grant enforcement; `internal/broker/` cache invalidation |
| S-RM-8 | 4 | Approvals expire automatically | `internal/gateway/team_jwt.go`; `--max-uses=0` rejection in gateway token mint |
| S-RM-9 | 5 | No secret leaves your machine | `internal/gateway/` local gateway; `internal/runner/` subprocess injection |

## User-facing command reference

```
keylatch security          — print the five invariants
keylatch audit tail        — watch the audit log live
keylatch audit since 1h    — review events from the past hour
keylatch doctor            — system health check
```

## Related

- [`docs/security/threat-model.md`](threat-model.md) — what Keylatch defends against and what it does not
- [`docs/verifying-releases.md`](../verifying-releases.md) — cosign + SBOM verification
