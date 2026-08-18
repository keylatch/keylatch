---
title: Environment Variables
since: 1.0.0
---

# Keylatch Environment Variables

This document lists every `KEYLATCH_*` environment variable that Keylatch reads, its purpose, whether it is security-sensitive, and whether it is forwarded to child processes.

**Child-env policy**: No `KEYLATCH_*` variable is *inherited* by child processes — the parent env is never passed through as-is. A small, explicitly re-injected set is written into the child env per runtime mode: `KEYLATCH_GATEWAY_TOKEN` + `KEYLATCH_GATEWAY_URL` + `KEYLATCH_RUNTIME` in gateway modes; `KEYLATCH_GATEWAY_URL` + `KEYLATCH_SESSION_TOKEN` + `KEYLATCH_CA_CERT` + `KEYLATCH_RUNTIME` in `gateway_proxy` mode. See [Child-env policy summary](#child-env-policy-summary). This prevents an agent from learning the vault path or backend configuration by running `env | grep KEYLATCH`.

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
| `KEYLATCH_EXPERIMENTAL` | Set to `1` to enable all experimental features, including the UI `/experimental` endpoint. Equivalent to setting `experimental_gated = true` in a custom-mode config. | No | Never |
| ~~`KEYLATCH_EXPERIMENTAL_BACKENDS`~~ | **Deprecated — ignored.** Previously gated the (now-removed) NordPass backend stub. | No | Never |

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
| `KEYLATCH_IPC_KEY_FD` | File descriptor for passing the daemon IPC HMAC key between processes (Unix — pipe-based, FIND2-002) | Yes | Never |
| `KEYLATCH_IPC_KEY` | Windows equivalent of `KEYLATCH_IPC_KEY_FD` — the daemon IPC HMAC key passed as a hex string (Windows cannot inherit a pipe FD the same way). Set by the Tauri desktop shell (`src-tauri/src/sidecar.rs`) when spawning `keylatchd`. **Note**: the Windows desktop shell is not shipped in the current release, so this path is compile-only today — no Go-side reader currently consumes it. | Yes | Never |
| `KEYLATCH_GRANT_ACCESSOR_KEY_PATH` | Path to the grant accessor HMAC key file | Yes | Never |
| `KEYLATCH_PKCS11_PIN` | **SECRET.** PKCS#11 module PIN, read only when a trust root's `PINSource` is configured as `env:KEYLATCH_PKCS11_PIN`. **Blocked inside LLM sessions** — `Open()` returns `ErrLLMSessionBlocked` before reading this var if `IsLLMSession()` is true (see `internal/trust/pkcs11/pkcs11.go`). Prefer `PINSource: "prompt"` or `"keychain"`. | Yes | Never |

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
| `KEYLATCH_GATEWAY_LISTEN` | Explicit non-loopback bind address for `keylatch gateway up` (e.g. `0.0.0.0:7878`), for Docker/container reachability. Opt-in only — an alternative to `--unsafe-bind-all` that lets the operator pick the exact advertised address. Precedence: `--listen` flag > `KEYLATCH_GATEWAY_LISTEN` > default (`--unsafe-bind-all` → `0.0.0.0:<port>`, else `127.0.0.1:<port>`). Still refused (fail-closed) when an LLM session is detected — see `internal/gateway/bind_resolve.go`. | No | Never |
| `KEYLATCH_GATEWAY_CONFIG` | Gateway config file path | No | Never |
| `KEYLATCH_GATEWAY_DIR` | Gateway state directory | No | Never |
| `KEYLATCH_GATEWAY_LOG` | Gateway log file path | No | Never |
| `KEYLATCH_GATEWAY_PID` | Gateway PID file path | No | Never |
| `KEYLATCH_GATEWAY_RULES` | Gateway policy rules file path | No | Never |
| `KEYLATCH_GATEWAY_TOKENS` | Gateway token store path | No | Never |
| `KEYLATCH_GATEWAY_TOKEN` | **Child-env only** — session token for the gateway (re-injected, not inherited) | Yes | gateway_typed/gateway_sdk only |
| `KEYLATCH_GATEWAY_URL` | **Child-env only** — gateway base URL (re-injected, not inherited). In `gateway_proxy` mode this is re-injected to point at the local MITM proxy address instead of the gateway, alongside `KEYLATCH_SESSION_TOKEN` and `KEYLATCH_CA_CERT` — see [Proxy Variables](#proxy-variables). | No | all gateway-family modes (value differs per mode) |

---

## Proxy Variables

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_PROXY_ADDR` | MITM proxy listen address | No | gateway_proxy only (explicitly re-injected) |
| `KEYLATCH_SESSION_TOKEN` | **Child-env only** — opaque per-session bearer token generated by the local MITM proxy (`EnsureToken()`), random and minted per proxy start, not a JWT and not the gateway token-store token. Injected only into the intended child process by `proxy.EnvInject` (`internal/proxy/env_proxy.go`) so the child's outbound HTTP calls can authenticate to the MITM proxy | Yes | gateway_proxy only (re-injected) |
| `KEYLATCH_CA_CERT` | **Child-env only** — path to the proxy's CA certificate, injected into the child so TLS-intercepted requests validate; only present when the proxy has a CA configured | No | gateway_proxy only (re-injected) |

---

## Backend Variables

These variables configure specific credential backends. They are read by the parent Keylatch process and are never inherited by child commands.

Several cloud/SaaS backends also accept **non-`KEYLATCH_*` aliases** — the
conventional env vars used by each provider's own SDK/CLI — via
`setIfEnv()` in `internal/backend/dispatch/dispatch.go`. Resolution order for
every settings field is: **config.json field → `KEYLATCH_*` var → alias var
→ backend-internal default.** The alias is only consulted if both the config
field and the `KEYLATCH_*` var are empty.

| Variable | Purpose | Security-sensitive | Child-env | Non-`KEYLATCH_*` alias |
|----------|---------|-------------------|-----------|--------------------------|
| `KEYLATCH_OP_BIN` | Override path to the `op` CLI binary | No | Never | — |
| `KEYLATCH_OP_VAULT` | 1Password vault name | No | Never | — |
| `KEYLATCH_BW_BIN` | Override path to the `bw` CLI binary | No | Never | — |
| `KEYLATCH_BW_SERVER` | Bitwarden/Vaultwarden server URL | No | Never | — |
| `KEYLATCH_BW_FOLDER` | Bitwarden folder filter | No | Never | — |
| `KEYLATCH_BW_COLLECTION` | Bitwarden collection filter | No | Never | — |
| `KEYLATCH_BW_SESSION_DIR` | Directory for cached Bitwarden session tokens and expiry metadata (default: `~/.keylatch/sessions`) | Yes | Never | — |
| `KEYLATCH_PROTON_PASS_BIN` | Override path to the Proton Pass CLI binary | No | Never | — |
| `KEYLATCH_PROTON_PASS_VAULT` | Proton Pass vault name | No | Never | — |
| `KEYLATCH_PROTON_PASS_ITEM_PREFIX` | Prefix for Proton Pass item names | No | Never | — |
| `KEYLATCH_KEEPER_BIN` | Override path to Keeper Commander | No | Never | — |
| `KEYLATCH_KEEPER_ACCOUNT_UID` | Keeper account UID for disambiguation | No | Never | — |
| `KEYLATCH_LASTPASS_BIN` | Override path to the `lpass` CLI binary | No | Never | — |
| `KEYLATCH_LASTPASS_USERNAME` | LastPass account username for disambiguation | No | Never | — |
| `KEYLATCH_VAULT_ADDR` | HashiCorp Vault address | No | Never | `VAULT_ADDR` |
| `KEYLATCH_VAULT_TOKEN` | HashiCorp Vault token | Yes | Never | `VAULT_TOKEN` |
| `KEYLATCH_VAULT_ROLE_ID` | HashiCorp Vault AppRole role ID | No | Never | — |
| `KEYLATCH_VAULT_SECRET_ID` | HashiCorp Vault AppRole secret ID | Yes | Never | — |
| `KEYLATCH_VAULT_MOUNT` | HashiCorp Vault KV mount | No | Never | — |
| `KEYLATCH_VAULT_KV_VERSION` | HashiCorp Vault KV version (`1` or `2`) | No | Never | — |
| `KEYLATCH_VAULT_NAMESPACE` | HashiCorp Vault Enterprise namespace | No | Never | `VAULT_NAMESPACE` |
| `KEYLATCH_AWS_SM_REGION` | AWS Secrets Manager region | No | Never | `AWS_REGION`, then `AWS_DEFAULT_REGION` |
| `KEYLATCH_AWS_ACCESS_KEY_ID` | AWS access key ID for static credentials | Yes | Never | `AWS_ACCESS_KEY_ID` |
| `KEYLATCH_AWS_SECRET_ACCESS_KEY` | AWS secret access key for static credentials | Yes | Never | `AWS_SECRET_ACCESS_KEY` |
| `KEYLATCH_AWS_SM_FORCE_DELETE` | AWS Secrets Manager force-delete flag | No | Never | — |
| `KEYLATCH_GCP_PROJECT_ID` | GCP project ID for Secret Manager | No | Never | `GOOGLE_CLOUD_PROJECT`, then `GCLOUD_PROJECT` |
| `KEYLATCH_GCP_CREDENTIALS_JSON` | Path to a GCP service-account JSON file | Yes | Never | `GOOGLE_APPLICATION_CREDENTIALS` |
| `KEYLATCH_AZURE_KV_URL` | Azure Key Vault URL | No | Never | — |
| `KEYLATCH_AZURE_VAULT_URL` | Alias for `KEYLATCH_AZURE_KV_URL` | No | Never | — |
| `KEYLATCH_AZURE_TENANT_ID` | Azure tenant ID | No | Never | `AZURE_TENANT_ID` |
| `KEYLATCH_AZURE_CLIENT_ID` | Azure client ID | No | Never | `AZURE_CLIENT_ID` |
| `KEYLATCH_AZURE_CLIENT_SECRET` | Azure client secret | Yes | Never | `AZURE_CLIENT_SECRET` |
| `KEYLATCH_DOPPLER_TOKEN` | Doppler API/service token | Yes | Never | `DOPPLER_TOKEN` |
| `KEYLATCH_DOPPLER_PROJECT` | Doppler project name | No | Never | `DOPPLER_PROJECT` |
| `KEYLATCH_DOPPLER_CONFIG` | Doppler config name | No | Never | `DOPPLER_CONFIG` |
| `KEYLATCH_DOPPLER_BASE_URL` | Doppler API base URL override | No | Never | — |
| `KEYLATCH_INFISICAL_BASE_URL` | Infisical API base URL override | No | Never | `INFISICAL_API_URL` |
| `KEYLATCH_INFISICAL_CLIENT_ID` | Infisical Universal Auth client ID | No | Never | `INFISICAL_CLIENT_ID` |
| `KEYLATCH_INFISICAL_CLIENT_SECRET` | Infisical Universal Auth client secret | Yes | Never | `INFISICAL_CLIENT_SECRET` |
| `KEYLATCH_INFISICAL_WORKSPACE_ID` | Infisical workspace ID | No | Never | `INFISICAL_WORKSPACE_ID` |
| `KEYLATCH_INFISICAL_ENVIRONMENT` | Infisical environment name | No | Never | `INFISICAL_ENVIRONMENT` |
| `KEYLATCH_INFISICAL_SECRET_PATH` | Infisical secret path | No | Never | `INFISICAL_SECRET_PATH` |
| `KEYLATCH_OP_CONNECT_URL` | 1Password Connect server URL | No | Never | `OP_CONNECT_HOST` |
| `KEYLATCH_OP_CONNECT_TOKEN` | 1Password Connect bearer token | Yes | Never | `OP_CONNECT_TOKEN` |
| `KEYLATCH_OP_CONNECT_VAULT_ID` | 1Password Connect vault UUID | No | Never | `OP_CONNECT_VAULT_ID` |

---

## Actor / Session Variables

| Variable | Purpose | Security-sensitive | Child-env |
|----------|---------|-------------------|-----------|
| `KEYLATCH_ACTOR` | Actor identifier for audit events (HMAC'd before use) | No | Never |
| `KEYLATCH_ACTORS_PATH` | Path to the actors definition file | No | Never |
| `KEYLATCH_MEMBER_ID` | Team member identifier | No | Never |
| `KEYLATCH_SESSIONS_PATH` | Path to the sessions store | No | Never |
| `KEYLATCH_DAEMON_STATE_PATH` | Override the path to `keylatchd`'s daemon-state JSON file (default `daemon-state.json` in the config dir), which stores lifecycle flags such as `first_launch_done`. Read/written by `paths.DaemonState()` and loaded in `cmd/keylatchd/main.go` to gate the first-launch notification. | No | Never |
| `KEYLATCH_DAEMON_SOCKET` | Path to the `keylatchd` LLM-session Unix domain socket. When set, the CLI queries the daemon's `/v1/llm-session` endpoint to check whether the current PID is a registered LLM session (Priority-2 check in `IsLLMSession`, fail-closed on any error). If unset, this IPC check is skipped entirely. | No | Never |
| `KEYLATCH_LLM_TICKET` | Signed session ticket issued by keylatchd; presence indicates an active LLM session (fast-path gate for `IsLLMSession`) | Yes | Never |
| `KEYLATCH_ALLOW_UNVERIFIED_SESSION` | Set to `1` to opt out of raw-credential session verification for this invocation. When set, `keylatch get` and direct-mode `keylatch run` no longer require a signed ticket or a reachable `keylatchd` before exposing a raw secret. Equivalent to the persistent `allow_unverified_session: true` field in `config.json`. Leave unset (the default) to fail closed. | No | Never |

> **Raw-credential session verification.** `keylatch get` and `keylatch run` in a raw-credential-exposure mode (`direct_brokered`, `direct_classic_sandboxed`) require positive proof the caller is trusted — a signed `KEYLATCH_LLM_TICKET` **or** a reachable `keylatchd` (`KEYLATCH_DAEMON_SOCKET`) — before handing a real secret to the child. Without either they fail closed (exit code 2) for *every* session, even one that has unset all LLM-detection signals to look human. Gateway/proxy modes (`gateway_typed`, `gateway_sdk`, `gateway_proxy`) are never gated by this check because the child receives only a scoped session token, never a raw secret. To run raw-credential paths without `keylatchd`, opt out via `KEYLATCH_ALLOW_UNVERIFIED_SESSION=1` (per invocation) or `allow_unverified_session: true` in `config.json` (persistent).

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
| `KEYLATCH_UI_ADDR` | Override the UI server listen address | No | Never |
| `KEYLATCH_UI_LISTEN` | Explicit non-loopback bind address for `keylatch ui` (e.g. `0.0.0.0:7890`), for Docker/container reachability. Opt-in only — an alternative to `--unsafe-bind-all` that lets the operator pick the exact advertised address. Precedence: `--listen` flag > `KEYLATCH_UI_LISTEN` > default (`--unsafe-bind-all` → `0.0.0.0:<port>`, else `127.0.0.1:<port>`). Still refused (fail-closed) when an LLM session is detected — see `internal/ui/bind_resolve.go`. | No | Never |

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
#   Child env is rebuilt from scratch — base env is PATH, HOME, USER, TERM,
#   LANG, LC_ALL, TMPDIR, TMP, TEMP only (proxyBaseEnv() in
#   internal/runner/driver_proxy.go). SHELL is NOT included.
#   proxy.EnvInject() then adds: KEYLATCH_GATEWAY_URL, KEYLATCH_SESSION_TOKEN,
#   KEYLATCH_CA_CERT (only if a CA is configured), KEYLATCH_RUNTIME.
#   Any --extra vars requested by the caller are also copied in from the
#   parent env by name (ExtraEnvVars), on top of this base.
```

This is enforced by `runtime.FilterChildEnv` (T-08-01) in every runtime driver, and by `proxy.EnvInject` specifically for `gateway_proxy`.
