# Security Invariants

Keylatch enforces five user-facing security properties at runtime:

| # | Invariant | What it means |
|---|-----------|---------------|
| 1 | Agents use secrets only through brokered actions | An agent uses a secret through `run`, `call`, the gateway or `mint`, under policy and with audit, and never receives the credential. The protection differs by mode, stated below. |
| 2 | Every secret use is logged | Every read, write, decrypt, and policy-check is written to the append-only HMAC-chained audit log. |
| 3 | Revoking access is instant | Removing a grant or connection takes effect on the next request — no TTL propagation delay. |
| 4 | Approvals expire automatically | Gateway tokens and approval JWTs have mandatory TTLs. Unlimited-TTL tokens are rejected. |
| 5 | The raw credential is sent only to the allowlisted provider endpoint | The gateway holds the provider key and sends it only to the endpoint a provider template allowlists; a child process, an upstream redirect or a response never receives it. |

## Invariant 1 per mode

| Mode | Statement |
|------|-----------|
| In-user (this release) | Brokered actions never hand an agent the credential, and policy denies by default. An agent running as your own user can still read files your account can read or run a modified binary, so this is defense in depth, not a boundary. See [`threat-model.md`](threat-model.md). |
| Broker daemon (v0.11.0 and later) | Every key lives under a separate OS user. An agent reaches only connections whose policy allows its caller kind, and privileged changes need a presence proof the daemon verifies. |

## Cross-reference: internal IDs

The invariants above correspond to the following internal security requirements. The internal IDs appear only in this file and in the codebase — not on user-facing surfaces.

| Internal ID | Invariant # | User-facing description | Enforcing code / config |
|-------------|-------------|------------------------|------------------------|
| S-RM-1 | 1 | Agents use secrets only through brokered actions | `internal/cli/guard.go` `GuardLLMSession`; `internal/policy/enforce/enforce.go` `Decide`; `internal/presence/presence.go` `Require`; `contrib/agent-guards/claude-code/block-keylatch-exfiltration.sh` |
| S-RM-3 | 2 | Every secret use is logged | `internal/audit/audit.go` `Logger.Log`; all action constants in `audit.go` |
| S-RM-6 | 3 | Revoking access is instant | `internal/grant/grant.go` grant enforcement; `internal/broker/` cache invalidation |
| S-RM-8 | 4 | Approvals expire automatically | `internal/gateway/team_jwt.go`; `--max-uses=0` rejection in gateway token mint |
| S-RM-9 | 5 | The raw credential is sent only to the allowlisted provider endpoint | `internal/gateway/` local gateway and SSRF gate; `internal/runner/` subprocess injection |

## User-facing command reference

```
keylatch security          — print the five invariants
keylatch audit tail        — watch the audit log live
keylatch audit since 1h    — review events from the past hour
keylatch doctor            — system health check
```

## Related

- [`docs/security/threat-model.md`](threat-model.md) — what Keylatch defends against and what it does not
- [`docs/policy.md`](../policy.md) — who may use a connection, and how
- [`docs/verifying-releases.md`](../verifying-releases.md) — cosign + SBOM verification
