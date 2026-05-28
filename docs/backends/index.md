---
title: Backends
since: 0.1.0
---

# Backends

Keylatch supports 14 credential store backends. Choose the one that fits your environment.

Set the active backend:

```bash
keylatch config set backend <name>
# or
export KEYLATCH_BACKEND=<name>
```

---

## Capabilities matrix

| Backend | Config key | Platform | Encrypted | Biometric | Team sharing | Offline | Required binary |
|---------|-----------|----------|:---------:|:---------:|:------------:|:-------:|-----------------|
| Encrypted file | `file` | All | Yes (XChaCha20) | No | No | Yes | — |
| macOS Keychain | `keychain` | macOS | Yes (system) | Yes (Touch ID) | No | Yes | — |
| 1Password | `op` | All | Yes | Yes | Yes | No | `op` v2+ |
| Bitwarden | `bw` | All | Yes | No | Yes | Partial | `bw` |
| ProtonPass | `protonpass` | All | Yes | No | Yes | No | `proton-pass` |
| Keeper | `keeper` | All | Yes | No | Yes | No | `keeper` |
| LastPass | `lastpass` | All | Yes | No | Yes | No | `lpass` |
| HashiCorp Vault | `vault` | All | Yes | No | Yes | No | `vault` |
| AWS Secrets Manager | `awssm` | All | Yes (cloud) | No | Yes | No | — (AWS SDK) |
| 1Password Connect | `opconnect` | All | Yes | No | Yes | No | — (HTTP) |
| GCP Secret Manager | `gcpsm` | All | Yes (cloud) | No | Yes | No | — (GCP SDK) |
| Azure Key Vault | `azurekv` | All | Yes (cloud) | No | Yes | No | — (Azure SDK) |
| Doppler | `doppler` | All | Yes (cloud) | No | Yes | No | — (HTTP) |
| Infisical | `infisical` | All | Yes (cloud) | No | Yes | No | — (HTTP) |

---

## Setup — top 4 backends

### `file` — Encrypted file (default)

Stores credentials in `~/.keylatch/vault/` as XChaCha20-Poly1305 AEAD-encrypted blobs.
The encryption key (DEK) is wrapped by a platform KEK stored in the macOS Keychain or
an age-env identity file. No external dependencies.

```bash
keylatch config set backend file
keylatch bootstrap          # creates ~/.keylatch/vault/ with mode 0700 and initializes keyring
keylatch connect openrouter api_key YOUR_KEY
```

Override the vault directory:

```bash
export KEYLATCH_VAULT_PATH=/custom/path/vault
```

The `file` backend is suitable for CI headless use. The vault is encrypted at rest
(XChaCha20-Poly1305; AES-256-GCM when `KEYLATCH_FIPS=1`) and requires no external
services. See [backends/file.md](file.md) for full security invariants.

---

### `keychain` — macOS Keychain

Uses the macOS Security framework. Entries are protected by the login keychain and may require Touch ID or password. Survives reboots without re-entry.

```bash
keylatch config set backend keychain
keylatch connect openrouter api_key YOUR_KEY
```

macOS only. iCloud Keychain sync is not enabled — local keychain only.

---

### `op` — 1Password CLI

Delegates all storage to 1Password via the `op` CLI (version 2+). Keylatch writes items tagged `Keylatch` in the configured vault.

```bash
op signin
keylatch config set backend op
keylatch connect openrouter api_key YOUR_KEY
```

CI / non-interactive:

```bash
export OP_SERVICE_ACCOUNT_TOKEN="ops_..."
export KEYLATCH_BACKEND=op
keylatch connect openrouter api_key YOUR_KEY
```

| Env var | Purpose |
|---------|---------|
| `KEYLATCH_OP_VAULT` | Vault name (default: `Keylatch`) |
| `KEYLATCH_OP_BIN` | Path to `op` binary (default: PATH) |
| `OP_SERVICE_ACCOUNT_TOKEN` | Service account token for CI |

---

### `bw` — Bitwarden / Vaultwarden

Delegates storage to the Bitwarden CLI (`bw`). Works with hosted Bitwarden and self-hosted Vaultwarden instances.

```bash
export BW_SESSION=$(bw unlock --raw)
keylatch config set backend bw
keylatch connect openrouter api_key YOUR_KEY
```

| Env var | Purpose |
|---------|---------|
| `BW_SESSION` | Session token from `bw unlock --raw` |
| `KEYLATCH_BW_SERVER` | Vaultwarden server URL (`https://` required) |
| `KEYLATCH_BW_BIN` | Path to `bw` binary (default: PATH) |
| `KEYLATCH_BW_FOLDER` | Filter items by folder name |
| `KEYLATCH_BW_COLLECTION` | Filter items by collection ID |

---

## Setup — remaining 10 backends

For the remaining backends, set `KEYLATCH_BACKEND=<key>` and consult the provider's own documentation for authentication setup.

| Backend | Config key | Docs |
|---------|-----------|------|
| ProtonPass | `protonpass` | [proton.me/pass](https://proton.me/pass) |
| Keeper | `keeper` | [docs.keeper.io](https://docs.keeper.io/developer-and-api-documentation) |
| LastPass | `lastpass` | [support.lastpass.com](https://support.lastpass.com/s/article/lastpass-command-line-application) |
| HashiCorp Vault | `vault` | [vaultproject.io](https://developer.hashicorp.com/vault/docs) |
| AWS Secrets Manager | `awssm` | [AWS docs](https://docs.aws.amazon.com/secretsmanager/latest/userguide/) |
| 1Password Connect | `opconnect` | [1Password Connect docs](https://developer.1password.com/docs/connect/) |
| GCP Secret Manager | `gcpsm` | [GCP docs](https://cloud.google.com/secret-manager/docs) |
| Azure Key Vault | `azurekv` | [Azure docs](https://learn.microsoft.com/en-us/azure/key-vault/) |
| Doppler | `doppler` | [doppler.com/docs](https://docs.doppler.com) |
| Infisical | `infisical` | [infisical.com/docs](https://infisical.com/docs) |

---

## Headless CI — using the encrypted vault without a prompt

The `file` backend uses a platform KEK (macOS Keychain or age-env identity file)
to unlock the vault. No passphrase is required. In CI you have two options:

### Option 1 — `--provider-ref` (no local vault required)

Resolve credentials directly from an external store at connect time. The vault
passphrase is never involved:

```bash
# 1Password service account (set OP_SERVICE_ACCOUNT_TOKEN in CI)
keylatch connect openrouter --provider-ref api_key=op://CI-Vault/OpenRouter/api_key

# AWS Secrets Manager (IAM role or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
keylatch connect openrouter --provider-ref api_key=aws-sm://us-east-1/openrouter-api-key

# HashiCorp Vault (VAULT_TOKEN / VAULT_ADDR)
keylatch connect openrouter --provider-ref api_key=hashivault://secret/openrouter#api_key
```

### Option 2 — system keyring (macOS / Linux with libsecret)

Switch to the `keychain` (macOS) backend so the OS keyring manages the secret.
Most CI runners that target macOS support this out of the box via the login
keychain unlocked at session start.

```bash
export KEYLATCH_BACKEND=keychain
keylatch connect openrouter api_key "$OPENROUTER_KEY"
```

### Recommendation

For ephemeral CI pipelines (GitHub Actions, GitLab CI, CircleCI) the
`--provider-ref` approach (Option 1) is preferred because it avoids storing a
vault file in the runner at all — credentials are fetched from a managed secret
store on demand and never written to disk by keylatch.

**Note**: `KEYLATCH_PASSPHRASE` has no effect on the `file` backend (S-FIND-12).
The passphrase env var is not read during bootstrap or credential access.

---

## Diagnostics

```bash
keylatch doctor           # check backend availability and auth state
keylatch doctor --json    # machine-readable output
```

## Switching backends

To migrate credentials from one backend to another:

1. Export from the current backend (or note the values).
2. `keylatch config set backend <new>`.
3. Re-connect with `keylatch connect <provider> <field> <value>`.

There is no automated migration — credential values must be re-entered or scripted.

---

Also see: [docs/backends.md](../backends.md) for the original backend overview.
