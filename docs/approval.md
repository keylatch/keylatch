# Approval System

Keylatch's approval system lets human operators review and act on secret-access requests before they are served to an LLM session or agent process.

## Overview

When an LLM session requests a credential through the gateway, keylatch can require a human to approve the request before it proceeds. Pending requests are persisted to `~/.keylatch/approvals/` and survive restarts.

The `keylatch approve` and `keylatch deny` commands are **always blocked inside LLM sessions** (exit 2, SecurityBlock) — this is a safety invariant. Approvals must be performed by a human operator in a separate terminal.

---

## Commands

### `keylatch approve <token>`

Approve a pending secret-access request by token.

```
keylatch approve apv_<token>
keylatch approve apv_<token> --reason "reviewed and looks fine"
keylatch approve apv_<token> --json
```

| Flag | Description |
|------|-------------|
| `--reason <text>` | Record a reason (stored in the approval file for audit) |
| `--json` | Output result as JSON |

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Approved successfully |
| 1 | Token already approved or denied |
| 2 | Blocked — LLM session detected |
| 3 | Token not found |
| 5 | Unexpected error |

**Error: expired token**

If a request's TTL has elapsed, `approve` exits 1 with:
```
approval "apv_..." expired at <timestamp> and was auto-denied
Ask the agent to re-submit.
```

---

### `keylatch approve list`

List all pending approval requests.

```
keylatch approve list
keylatch approve list --json
```

Output columns: `ID | PROVIDER | AGENT | REQUESTED-AT | TTL-REMAINING | STATUS`

Entries past their TTL are shown with `STATUS=expired` — they can no longer be approved and will be cleaned up by the background sweep.

| Flag | Description |
|------|-------------|
| `--json` | Output as a JSON array |

---

### `keylatch deny <token>`

Deny a pending secret-access request by token.

```
keylatch deny apv_<token>
keylatch deny apv_<token> --reason "wrong environment"
keylatch deny apv_<token> --json
```

| Flag | Description |
|------|-------------|
| `--reason <text>` | Record a reason (recommended for audit trail) |
| `--json` | Output result as JSON |

---

### `keylatch deny --all`

Deny every pending approval in one operation.

```
keylatch deny --all
keylatch deny --all --yes
keylatch deny --all --yes --json
```

Without `--yes`, you are prompted:
```
Deny all 3 pending approvals? [y/N]
```

| Flag | Description |
|------|-------------|
| `--all` | Deny all pending approvals |
| `--yes` | Skip confirmation prompt |
| `--json` | Emit `{"deniedCount": N, "requestIds": [...]}` |

Race tolerance: if a request is approved or denied by another operator between the list and the deny, it is silently skipped.

---

## Approval Policy

Each connection can be configured with an `approval_mode` that determines when human approval is required.

### Modes

| Mode | Description |
|------|-------------|
| `trust` | Auto-approve every request. No human interaction needed. |
| `first-run` | Require approval for the first request per session per (actor, capability, connection) triple. Identical subsequent requests are auto-approved. |
| `prompt` | Require explicit human approval for every request. |

### Defaults

| Runtime path | Default mode |
|---|---|
| `gateway_typed`, `gateway_sdk`, `gateway_proxy` | `trust` |
| `direct_brokered` and value-bearing paths | `first-run` |

### Configuration

Set `approval_mode` in your connection YAML:

```yaml
# ~/.keylatch/config.yaml (per-connection override)
connections:
  openrouter:
    approval_mode: prompt   # require approval every time
  anthropic:
    approval_mode: trust    # auto-approve (gateway path already isolates)
```

When `approval_mode` is not set, the mode is derived from the runtime context via `DefaultMode`.

---

## TTL and Auto-Deny

Every approval request has an `ExpiresAt` timestamp. Requests past their TTL:

- Are shown as `STATUS=expired` in `approve list`
- Cannot be approved — `keylatch approve <token>` exits 1 with an actionable message
- Are permanently denied by the background sweep (run by the gateway process on a timer)
- Show `"auto-denied by TTL sweep"` in the approval file `note` field

Default TTL is **15 minutes**. The TTL is set at request creation time by the caller (gateway or broker).

---

## Audit Trail

Every approval or denial is recorded:
- The approval file at `~/.keylatch/approvals/<token>.json` stores `status`, `note`, `actor`, and timestamps.
- The keylatch audit log captures the decision event.

Use `keylatch audit` to inspect the audit log.
