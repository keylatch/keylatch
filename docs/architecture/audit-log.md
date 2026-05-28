---
title: Audit Log Architecture
since: 1.0.0
---

# Audit Log Architecture

## Overview

The Keylatch audit log records every credential access, runtime decision, LLM session gate result, and security block. The log is append-only and chain-MAC'd so that tampering with any event in the middle of the log is detectable.

---

## Chain MAC Design

Each audit event has a `chain_hmac` header field computed as:

```
chain_hmac[i] = HMAC-SHA256(salt, event_body[i] || chain_hmac[i-1])
```

The chain MAC key is derived from the **salt file only** (`~/.keylatch/audit/salt`, 32 bytes, randomly generated on first run).

### Integrity vs. Verifiability Trade-off

This design makes an explicit trade-off:

| Property | Result |
|----------|--------|
| Chain integrity without the DEK | Yes — anyone with read access to the salt can verify the chain |
| Chain forgery with salt access | Yes — anyone with read access to the salt can forge chain **headers** |
| Event body integrity | Strong — events are AEAD-encrypted (xchacha20-poly1305) under the DEK; forging body content requires the DEK even if the salt is known |
| Repudiation of individual events | No — no per-event asymmetric signature |

**Chain MAC key derivation:**

The chain MAC key is derived from the salt file only — not from the DEK:

```
chain_mac_key = HKDF-SHA256(ikm=salt, info="keylatch/audit/mac-key/v1")
```

This allows `keylatch audit verify` to check chain integrity in header-only mode (without needing the DEK). The trade-off is that anyone who can read the salt file can forge chain headers. Event body AEAD authentication still detects tampering of event bodies even if an attacker knows the chain MAC key.

**Why this is an acceptable trade-off:**

1. The salt file lives at `~/.keylatch/audit/salt` with mode `0600` and its directory at mode `0700`. Only the owning user can read it. The OS file permission system is the primary enforcement control.

2. An attacker who has gained read access to the salt has already achieved local file-system access at user level — a condition in which the audit log is forensics evidence, not a security control.

3. Chain MAC forgery requires read access to the salt AND write access to the audit log — two independent conditions. A read-only attacker can verify the chain but cannot inject forged headers without write access.

4. The `keylatch doctor` check A5 asserts salt file permissions (`0600`) and directory permissions (`0700`) on every health check, providing a continuous monitoring signal if permissions are inadvertently relaxed.

5. The CI script `scripts/lint-audit-perms.sh` (T-11-02, S-FIND-14) asserts the same permission invariants in continuous integration. It is run as part of the `policy-lint` job in `.github/workflows/ci.yml`. See [EPIC-06 P1 security findings](#security-invariants) for the full finding.

6. For environments where stronger audit integrity is required, Keylatch supports forwarding audit events to an external SIEM via `audit.ForwardURL`. The external sink is the authoritative tamper-evident log in that configuration. See EPIC-12 (`keylatch doctor` and health-check improvements) for planned enhancements to automated permission repair and alerting.

---

## Cross-File Chain Continuity (T-13-07)

When the audit log is rotated (size-based or explicit `Rotate()` call), the chain
MAC continuity is preserved across the boundary using two sentinel events:

### Rotation Protocol

```
OLD FILE (audit.log.1):
  ... event[N-1]
  event[N]  — ActionAuditRotate, Extra["rotated_to"] = "audit.log.1"
              (this is the LAST line of the old file)

NEW FILE (audit.log):
  event[1]  — ActionAuditRotate, Extra["rotated_from"] = "audit.log.1",
               Extra["prev_file_hmac"] = HMAC_of_last_line_of_old_file
  event[2]  ...
```

### Cross-File Chain Invariant

The `prev_file_hmac` value in the new file's first event equals:

```
prev_file_hmac = HMAC-SHA256(chain_mac_key, last_raw_line_of_old_file)
```

This links the two files at their boundary. An auditor verifying cross-file
continuity must:

1. Compute `VerifyChain(old_file)` — verify the internal chain of the old file.
2. Read the last raw line of the old file and compute its HMAC.
3. Read the `prev_file_hmac` field from the first event of the new file.
4. Assert that (2) == (3).
5. Compute `VerifyChain(new_file)` — verify the internal chain of the new file.

### Why Sentinel Events Instead of a Header

Log entries are line-oriented and append-only. There is no structured file header
that could be updated after the rotation sentinel is written. Using sentinel events
(one at the end of the old file, one at the start of the new file) is consistent
with the existing append-only constraint and keeps all chain state within the log
lines themselves.

### `VerifyChain` Behaviour During Rotation

`VerifyChain` treats the first line of each file independently:
- Line 1 of a new file may have `seq=1` and a zero `prev_hmac` (fresh start),
  OR it may be a `rotation-continued` sentinel with `prev_file_hmac` in `Extra`.
- `VerifyChain` verifies the intra-file chain from line 1 → last line.
- Cross-file verification is the responsibility of the auditor tool
  (see `keylatch audit verify-chain --multi-file`).

### Test Coverage

`internal/audit/chain_rotation_test.go` (`TestAuditChainContinuityAcrossRotation`)
verifies the full rotation protocol:
- Old file passes `VerifyChain` independently.
- New file passes `VerifyChain` independently.
- `prev_file_hmac` in the new file's first event equals the HMAC of the old file's
  last raw line.

---

## Salt File

- **Location**: `${KEYLATCH_CONFIG_DIR}/audit/salt` (default: `~/.keylatch/audit/salt`)
- **Mode**: `0600` (user-read/write only)
- **Directory mode**: `0700`
- **Size**: 32 bytes (256 bits), randomly generated on bootstrap
- **Purpose**: HMAC key for chain integrity headers

The salt is generated once during `keylatch bootstrap` and never rotated. It is NOT the DEK — it does not decrypt event bodies.

---

## Token JTI Correlation (P1-16)

Every `keylatch run` that issues a `KEYLATCH_GATEWAY_TOKEN` records the token JTI (unique ID) in the corresponding audit event. This allows cross-referencing:

- The `run` audit event: contains `jti`, `actor_hmac`, `provider`, `capability`, `command_hmac`
- The gateway call audit events: contain the same `jti` for all requests made within that token's lifetime

JTI correlation makes it possible to reconstruct the full causal chain: which CLI invocation caused which upstream API calls, even when the token is shared between the issuing process and the gateway's audit log.

---

## Permission Checking

Run the CI lint script to assert correct permissions:

```bash
scripts/lint-audit-perms.sh
```

Exit 0 = permissions correct. Exit 1 = at least one permission is wrong (fix with `chmod 0600 ~/.keylatch/audit/salt; chmod 0700 ~/.keylatch/audit/`).

---

## Event Types

The following table lists all audit event types emitted by the vault layer. The `action` field is the string constant written to the log entry.

### Vault Credential Events (EPIC-14)

| Action constant | `action` string | Triggered by | Required fields | Notes |
|----------------|-----------------|--------------|-----------------|-------|
| `ActionRead` | `"read"` | `vault.Get` | `path`, `outcome`, `timestamp` | Emitted on success and failure. Credential value is NEVER included (S-RM-9). `Extra.error_class` set on failure. |
| `ActionWrite` | `"write"` | `vault.Set` | `path`, `outcome`, `timestamp` | Emitted on success and failure. Credential value bytes are NEVER included (S-RM-9). |
| `ActionDelete` | `"delete"` | `vault.Delete` | `path`, `outcome`, `timestamp` | Emitted on success and failure. `Extra.error_class` set on failure. |
| `ActionList` | `"list"` | `vault.List` | `path` (prefix), `outcome`, `timestamp`, `Extra.count` | `Extra.count` is the number of entries returned. Individual path names are NOT included in the event (S-RM-9). |

**Outcome values:** `"ok"` on success, `"error"` on any backend error (includes not-found). `Extra.error_class` is `"not_found"` when `backend.ErrNotFound` is returned, `"error"` for other errors.

**Safe-log-fields allowlist:** `fields.safeLogFields` permits `"count"` and `"prefix"` for the `"list"` action; `"version"`, `"backend"`, and `"key_term"` for `"read"` and `"write"` (note: `"delete"` does not permit `key_term` — only `"version"` and `"backend"`). All other `Extra` keys are HMAC-redacted before writing to the log.

**Emitter injection:** The vault layer retrieves the `audit.Emitter` from the `context.Context` via `audit.EmitterFromCtx`. The gateway handler (`handler.go`) and brokered runner (`driver_brokered.go`) inject the emitter before calling vault operations. The `list_cmd.go` CLI command also injects it. Commands using `vault.RotateValue` (e.g. `set_cmd.go`) emit via the `RotateValue` path fixed in EPIC-14. Commands using `vault.DestroyVersion` or other versioned operations do not yet inject the emitter. If no emitter is present, vault events are silently dropped — audit failures do not interrupt vault operations.

---

## Security Invariants

| Invariant | Property |
|-----------|----------|
| Salt file mode 0600 | Enforced by `salt.LoadOrCreate` on every read |
| Salt directory mode 0700 | Checked by `scripts/lint-audit-perms.sh` and doctor check A5 |
| Event body confidentiality | AEAD encryption under the DEK |
| Chain integrity | HMAC-SHA256 chain using the salt |
| Append-only | OS-level: log file has no truncation call sites in production code |
| No credential bytes in events | Enforced at all audit call sites — only HMAC'd actor IDs appear |
