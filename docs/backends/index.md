---
title: Backends
since: 0.1.0
---

# Backends

Keylatch supports 14 credential store backends. Choose the one that fits your environment.

Set the active backend:

```bash
keylatch config set backend <name>
```

`KEYLATCH_BACKEND=<name>` selects a backend only while `backend` is unset in `config.json`; the config value wins. `keylatch backend list` prints every backend with its support tier.

---

## Capabilities matrix

| Backend | Config key | Platform | Encrypted | Biometric | Team sharing | Offline | Required binary |
|---------|-----------|----------|:---------:|:---------:|:------------:|:-------:|-----------------|
| Encrypted file | `file` | All | Yes (XChaCha20) | No | No | Yes | — |
| macOS Keychain | `keychain` | macOS | Yes (system) | Yes (Touch ID) | No | Yes | — |
| 1Password | `op` | All | Yes | Yes | Yes | No | `op` v2+ |
| Bitwarden | `bw` | All | Yes | No | Yes | Partial | `bw` |
| ProtonPass | `proton-pass` | All | Yes | No | Yes | No | `proton-pass` |
| Keeper | `keeper` | All | Yes | No | Yes | No | `keeper` |
| LastPass | `lastpass` | All | Yes | No | Yes | No | `lpass` |
| HashiCorp Vault | `vault` | All | Yes | No | Yes | No | `vault` |
| AWS Secrets Manager | `aws-sm` | All | Yes (cloud) | No | Yes | No | — (AWS SDK) |
| 1Password Connect | `op-connect` | All | Yes | No | Yes | No | — (HTTP) |
| GCP Secret Manager | `gcp-sm` | All | Yes (cloud) | No | Yes | No | — (GCP SDK) |
| Azure Key Vault | `azure-kv` | All | Yes (cloud) | No | Yes | No | — (Azure SDK) |
| Doppler | `doppler` | All | Yes (cloud) | No | Yes | No | — (HTTP) |
| Infisical | `infisical` | All | Yes (cloud) | No | Yes | No | — (HTTP) |

---

## Setup — top 4 backends

### `file` — Encrypted file (default)

Stores credentials in `~/.keylatch/vault/` as XChaCha20-Poly1305 AEAD-encrypted blobs.
The encryption key (DEK) is wrapped by a KEK derived from a vault identity held in the
OS keyring (macOS Keychain or Secret Service). Hosts without a keyring use a passphrase
asked on a terminal; only the operator's config can allow a plaintext identity file. See
[File backend](file.md#where-the-vault-identity-lives).

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
(XChaCha20-Poly1305; AES-256-GCM in FIPS builds compiled with `-tags=fips`) and
requires no external services. See [backends/file.md](file.md) for full security
invariants.

---

### `keychain` — macOS Keychain (deprecated)

Deprecated: the macOS Keychain stays as a key store for the file backend's vault identity, not as a credential backend, and the backend will be removed. It is macOS only and reads the value from stdin, never from an argument.

```bash
keylatch config set backend keychain
printf '%s' "$OPENROUTER_KEY" | keylatch connect openrouter -f api_key=@-
```

Migrate to `op`, `bw` or `file`. iCloud Keychain sync is not enabled — local keychain only.

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

For CI, store the service account token with `keylatch backend login op` (see [Backend credentials](#backend-credentials)); an exported `OP_SERVICE_ACCOUNT_TOKEN` is refused unless `backends.op.allow_env_credentials` is `true`.

---

### `bw` — Bitwarden / Vaultwarden

Delegates storage to the Bitwarden CLI (`bw`). Works with hosted Bitwarden and self-hosted Vaultwarden instances.

```bash
keylatch bw unlock
keylatch config set backend bw
keylatch connect openrouter api_key YOUR_KEY
```

| Env var | Purpose |
|---------|---------|
| `KEYLATCH_BW_SERVER` | Vaultwarden server URL (`https://` required) |
| `KEYLATCH_BW_BIN` | Path to `bw` binary (default: PATH) |
| `KEYLATCH_BW_FOLDER` | Filter items by folder name |
| `KEYLATCH_BW_COLLECTION` | Filter items by collection ID |

**Folder.** With a folder configured, only items in that folder are listed or read; a new item is created in it.

**Server check.** When a server is configured (`KEYLATCH_BW_SERVER` or `bw.server`), `bw config server` must name the same server or the backend refuses with `ErrServerMismatch` before it sends anything. Run `bw config server <url>` to fix it.

**Organization collections.** To keep items in an organization's shared collections, give each namespace a collection:

```bash
keylatch setup --backend bw --organization-id <org-id> --server https://vault.example.com \
  --namespace work=Work/infra --namespace ops=Ops
```

which stores, in `config.json`:

```json
{ "bw": { "organization_id": "<org-id>", "namespaces": { "work": "Work/infra", "ops": "Ops" } } }
```

A path `work/deploy/api_key` is then created with the organization ID and the ID of the collection named `Work/infra` (resolved once per process with `bw list collections --organizationid <org-id>`), and is looked up only in that collection. A namespace with no entry — including `default` — is refused with `ErrNamespaceUnmapped` before any `bw` call. `bw.namespaces` needs `bw.organization_id` and replaces `bw.folder` and `bw.collection`.

**Session.** `keylatch bw unlock` seals the session token under the vault key (the same key that wraps the keyring) in `sessions/bw.session.enc`, keeps only its expiry beside it, and never writes it in plaintext. The session lasts 1 hour by default; `--ttl` or `bw.session_ttl` (a duration such as `30m`) sets it, up to 8 hours. The gateway holds the token in memory while it runs. `keylatch bw lock` deletes the sealed session and any `sessions/bw.session` plaintext file an earlier version left; `keylatch doctor` fails (`backend.bw_session_file`) while one is present.

---

## Setup — remaining 10 backends

For the remaining backends, set `KEYLATCH_BACKEND=<key>` and consult the provider's own documentation for authentication setup.

| Backend | Config key | Docs |
|---------|-----------|------|
| ProtonPass | `proton-pass` | [proton.me/pass](https://proton.me/pass) |
| Keeper | `keeper` | [docs.keeper.io](https://docs.keeper.io/developer-and-api-documentation) |
| LastPass | `lastpass` | [support.lastpass.com](https://support.lastpass.com/s/article/lastpass-command-line-application) |
| HashiCorp Vault | `vault` | [vaultproject.io](https://developer.hashicorp.com/vault/docs) |
| AWS Secrets Manager | `aws-sm` | [AWS docs](https://docs.aws.amazon.com/secretsmanager/latest/userguide/) |
| 1Password Connect | `op-connect` | [1Password Connect docs](https://developer.1password.com/docs/connect/) |
| GCP Secret Manager | `gcp-sm` | [GCP docs](https://cloud.google.com/secret-manager/docs) |
| Azure Key Vault | `azure-kv` | [Azure docs](https://learn.microsoft.com/en-us/azure/key-vault/) |
| Doppler | `doppler` | [doppler.com/docs](https://docs.doppler.com) |
| Infisical | `infisical` | [infisical.com/docs](https://infisical.com/docs) |

---

## Headless CI — using the encrypted vault without a prompt

The `file` backend derives its KEK from a vault identity in the OS keyring, or from a
plaintext identity file when the operator's config allows one (`scripts/ci-operator-config.sh`
does that on CI runners). No passphrase is required then. In CI you have two options:

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

### Option 2 — file backend with `allow_insecure_file_kek`

On a runner with no OS keyring and no terminal, `keylatch bootstrap` keeps the vault identity in a plaintext file next to the vault only when `allow_insecure_file_kek` is set in the operator's own config file (the default config path under the account's home); no flag or environment variable can set it. Any process on the runner can decrypt the vault, so use it only for throwaway runners, and expect `keylatch doctor` to fail on `backend.kek` there.

### Recommendation

For ephemeral CI pipelines (GitHub Actions, GitLab CI, CircleCI) the
`--provider-ref` approach (Option 1) is preferred because it avoids storing a
vault file in the runner at all — credentials are fetched from a managed secret
store on demand and never written to disk by keylatch.

**Note**: `KEYLATCH_PASSPHRASE` has no effect on the `file` backend.
The passphrase env var is not read during bootstrap or credential access.

---

## Backend credentials

Remote backends (`op`, `opconnect`, `vault`, `awssm`, `gcpsm`, `azurekv`, `doppler`, `infisical`) authenticate with a credential: a service account or Connect token, a Vault token or AppRole, an AWS key pair, a Google credentials file, an Azure client secret, a Doppler token, an Infisical client ID and secret. Keep it out of the environment:

```bash
keylatch backend login vault     # prompts on the terminal, stores it wrapped by the KEK
```

`backend login` is human-only: it needs an interactive terminal, refuses agent sessions, asks a human to approve the change before it prompts, and takes the value from the prompt, never from a flag or a pipe. It sets `backends.<id>.credential_ref` in the config. The backend reads the stored credential first; a stale variable in the environment does not override it.

Credentials exported in the environment (`VAULT_TOKEN`, `AWS_ACCESS_KEY_ID`, `DOPPLER_TOKEN`, ...) are refused with an explanation unless the config sets `backends.<id>.allow_env_credentials` to `true`; `keylatch doctor` warns while it is on. Every command Keylatch runs for you (`keylatch run`, the gateway runtimes, the MCP `keylatch_run` tool) starts with these variables and all `KEYLATCH_*` variables removed from its environment, whatever the parent exported.

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
