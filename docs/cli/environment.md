---
title: Environment Variables
since: 1.0.0
---

# Keylatch Environment Variables

This document lists every `KEYLATCH_*` environment variable that Keylatch reads, its purpose, whether it is security-sensitive, and whether it is forwarded to child processes.

**Child-env policy**: No `KEYLATCH_*` variable is forwarded to child processes. The only exception is `KEYLATCH_GATEWAY_TOKEN` and `KEYLATCH_GATEWAY_URL` in gateway modes, which are explicitly re-injected by the gateway driver (never inherited). This prevents an agent from learning the vault path or backend configuration by running `env | grep KEYLATCH`.

---

## Configuration Variables

These variables configure the Keylatch runtime. They are read by the CLI process and are **never** passed to child processes.

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_MODE` | Override operating mode for process lifetime (`standard`, `telemetry`, `canary`, `custom`). Takes precedence over config file value. | No | Never |
| `KEYLATCH_BACKEND` | Override the backend type (`file`, `keychain`, `op`, …) | No | Never |
| `KEYLATCH_CONFIG` | Path to the main `config.json` file | No | Never |
| `KEYLATCH_CONFIG_DIR` | Override the configuration directory (`~/.keylatch/`) | No | Never |
| `KEYLATCH_DATA_DIR` | Override the vault data directory (`~/.keylatch/vault/`) | No | Never |
| `KEYLATCH_VAULT_PATH` | Override the file backend vault path | No | Never |
| `KEYLATCH_NAMESPACE` | Override the default namespace (`default`) | No | Never |
| `KEYLATCH_LOG_LEVEL` | Log verbosity (`debug`, `info`, `warn`, `error`) | No | Never |
| `KEYLATCH_EXPERIMENTAL` | Set to `1` to enable all experimental features, including the NordPass backend stub and the UI `/experimental` endpoint. Equivalent to setting `experimental_gated = true` in a custom-mode config (EPIC-17). | No | Never |
| ~~`KEYLATCH_EXPERIMENTAL_BACKENDS`~~ | **Deprecated (EPIC-19) — ignored.** Previously gated the NordPass backend. Use `KEYLATCH_EXPERIMENTAL=1` instead. | No | Never |

---

## Crypto / Keyring Variables

These variables configure cryptographic operations. They are **security-sensitive** — exposure of these paths may assist an attacker.

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_AGE_IDENTITY` | Path to the age identity file for KEK derivation (age-env fallback) | Yes | Never |
| `KEYLATCH_KEYRING_DIR` | Override the keyring directory (`~/.keylatch/keyring/`) | Yes | Never |
| `KEYLATCH_KEYRING_PATH` | Override the keyring JSON path (`~/.keylatch/keyring.json`) | Yes | Never |
| `KEYLATCH_KEYRING_IDENTITY_PATH` | Override the age identity file path (`~/.keylatch/keyring/identity`) | Yes | Never |
| `KEYLATCH_GATEWAY_SIGNING_KEY` | Override path for the gateway signing key | Yes | Never |
| `KEYLATCH_IPC_KEY_FD` | File descriptor for passing the IPC key between processes | Yes | Never |
| `KEYLATCH_GRANT_ACCESSOR_KEY_PATH` | Path to the grant accessor HMAC key file | Yes | Never |

---

## Audit Variables

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_AUDIT_PATH` | Override the audit log directory | No | Never |
| `KEYLATCH_AUDIT_SALT_PATH` | Override the audit chain MAC salt file path | Yes | Never |

---

## Gateway Variables

These variables configure the gateway server and are written by `keylatch gateway up`. They are **read by the CLI process** to locate the running gateway and are never passed to child processes as-is.

In gateway modes, the child process receives `KEYLATCH_GATEWAY_TOKEN` and `KEYLATCH_GATEWAY_URL` — **explicitly re-injected** by the gateway driver, never inherited from the parent env.

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_GATEWAY_ADDR` | Gateway listen address override | No | Never |
| `KEYLATCH_GATEWAY_CONFIG` | Gateway config file path | No | Never |
| `KEYLATCH_GATEWAY_DIR` | Gateway state directory | No | Never |
| `KEYLATCH_GATEWAY_LOG` | Gateway log file path | No | Never |
| `KEYLATCH_GATEWAY_PID` | Gateway PID file path | No | Never |
| `KEYLATCH_GATEWAY_RULES` | Gateway policy rules file path | No | Never |
| `KEYLATCH_GATEWAY_TOKENS` | Gateway token store path | No | Never |
| `KEYLATCH_GATEWAY_TOKEN` | **Child-env only** — session token for the gateway (re-injected, not inherited) | Yes | gateway modes only |
| `KEYLATCH_GATEWAY_URL` | **Child-env only** — gateway base URL (re-injected, not inherited) | No | gateway modes only |

---

## Proxy Variables

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_PROXY_ADDR` | MITM proxy listen address | No | gateway_proxy only (explicitly re-injected) |

---

## Actor / Session Variables

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_ACTOR` | Actor identifier for audit events (HMAC'd before use) | No | Never |
| `KEYLATCH_ACTORS_PATH` | Path to the actors definition file | No | Never |
| `KEYLATCH_MEMBER_ID` | Team member identifier | No | Never |
| `KEYLATCH_SESSIONS_PATH` | Path to the sessions store | No | Never |
| `KEYLATCH_DAEMON_STATE_PATH` | Path to the keylatchd state socket/dir | No | Never |
| `KEYLATCH_LLM_TICKET` | Signed session ticket issued by keylatchd; presence indicates an active LLM session (fast-path gate for `IsLLMSession`) | Yes | Never |

---

## Team / Policy Variables

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_POLICY_PATH` | Override the policy YAML path | No | Never |
| `KEYLATCH_PROJECTS_PATH` | Path to the projects definition file | No | Never |
| `KEYLATCH_GRANTS_DIR` | Path to the grants directory | No | Never |
| `KEYLATCH_GRANTS_PATH` | Path to the grants JSON file | No | Never |
| `KEYLATCH_TEAM_DIR` | Team configuration directory | No | Never |
| `KEYLATCH_ORG_POLICY_DIR` | Org-level policy directory | No | Never |
| `KEYLATCH_APPROVALS_DIR` | Approval records directory | No | Never |

---

## Security-Sensitive Telemetry Variables

These variables control telemetry emission and are read by the CLI process before any event is sent.

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_TELEMETRY_DISABLE` | Set to `1` to suppress all telemetry regardless of operating-mode configuration. This is the operator kill-switch — takes precedence over every other telemetry setting. | No | Never |
| `KEYLATCH_TELEMETRY_URL` | Override the remote telemetry endpoint URL. Used in CI canary scans to redirect events to a local mock server. If unset, `https://telemetry.keylatch.dev/v1/events` is used. | No | Never |

---

## Miscellaneous Variables

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_RECEIPTS_PATH` | Path to the run receipts file | No | Never |
| `KEYLATCH_OP_BIN` | Override path to the `op` CLI binary | No | Never |
| `KEYLATCH_UI_ADDR` | Override the UI server listen address | No | Never |

---

## Runtime Identification (child-env only)

The runtime mode identifier `KEYLATCH_RUNTIME` is **written to** the child env (never inherited). It always contains the string name of the current runtime mode.

| Variable | Value in child env | Notes |
|----------|-------------------|-------|
| `KEYLATCH_RUNTIME` | `gateway_typed`, `gateway_sdk`, `direct_brokered`, `gateway_proxy` | Always present in child env in all runtime modes |

---

## Child-env policy summary

```
# Gateway modes (gateway_typed, gateway_sdk):
#   Child receives: KEYLATCH_GATEWAY_TOKEN, KEYLATCH_GATEWAY_URL, KEYLATCH_RUNTIME
#   Stripped:       ALL other KEYLATCH_* vars

# Brokered mode (direct_brokered):
#   Child receives: KEYLATCH_RUNTIME
#   Stripped:       ALL other KEYLATCH_* vars

# Proxy mode (gateway_proxy):
#   Child env is rebuilt from scratch (PATH, HOME, USER, SHELL, TERM, LANG, TMPDIR only)
#   No KEYLATCH_* vars are forwarded at all
```

This is enforced by `runtime.FilterChildEnv` (T-08-01) in every runtime driver.
