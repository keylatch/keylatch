---
title: File Backend
since: 0.1.0
---

# File Backend (`file`)

The `file` backend is the default keylatch credential store. It stores credentials
in `~/.keylatch/vault/` as AEAD-encrypted blobs on the local filesystem. No
external services or binaries are required.

## Security properties

| Property | Detail |
|----------|--------|
| Encryption algorithm | XChaCha20-Poly1305 (default); AES-256-GCM in FIPS builds (`-tags=fips`, not an env var — see [Security: FIPS compliance](../security.md#fips-compliance)) |
| Key derivation | KEK from platform keyring (macOS Keychain or age-env identity file) |
| On-disk format | `value.enc` (ciphertext) + `value.enc.nonce` + `value.enc.aad` per secret |
| Directory mode | 0o700 |
| File mode | 0o600 |
| Plaintext in storage | Never — CRIT-01 closed in EPIC-03 |

**S-INV-1 invariant**: no credential value is ever written to disk in plaintext or
base64 form. Every write goes through XChaCha20-Poly1305 AEAD (or AES-256-GCM
under a FIPS build). The on-disk `value.enc` contains only ciphertext.

## Setup

```bash
keylatch bootstrap          # creates ~/.keylatch/ with 0700, keyring with 0600
keylatch connect openrouter api_key YOUR_KEY
```

`bootstrap` initializes:
- `~/.keylatch/` (mode 0700)
- `~/.keylatch/vault/` (mode 0700)
- `~/.keylatch/audit.log` (mode 0600)
- `~/.keylatch/config.json` (mode 0600)
- `~/.keylatch/keyring/keyring.json` (mode 0600) — wraps the DEK with a platform KEK
- `~/.keylatch/keyring/identity` (mode 0600) — fallback age-env identity

### KEK selection

| Platform | KEK source |
|----------|-----------|
| macOS | macOS Keychain (`security add-generic-password`) |
| Linux / Windows | age-env identity file (`~/.keylatch/keyring/identity`) |

On macOS the Keychain is tried first; if unavailable (CI, container) the
age-env identity file is used as a fallback.

## Configuration

```bash
keylatch config set backend file

# Override the vault directory
export KEYLATCH_VAULT_PATH=/custom/path/vault

# Override the config directory
export KEYLATCH_CONFIG_DIR=/custom/path/.keylatch
```

## Re-initialization (`--force`)

To destroy and recreate the cryptographic keyring (e.g. after a KEK rotation):

```bash
keylatch bootstrap --force
```

This prompts for confirmation before removing the existing keyring. All
credentials encrypted under the previous DEK will be inaccessible afterward.

**Warning**: `--force` permanently destroys the keyring. Export any credentials
you need before proceeding.

## CI / headless use

The `file` backend works in headless CI environments:

```bash
# GitHub Actions example
- name: bootstrap keylatch
  run: keylatch bootstrap
  env:
    KEYLATCH_CONFIG_DIR: /tmp/.keylatch

- name: store secret
  run: printf '%s' "$API_KEY" | keylatch connect openrouter api_key=@-
  env:
    KEYLATCH_CONFIG_DIR: /tmp/.keylatch
```

On Linux CI runners the age-env identity file is used as the KEK source.
The identity file must persist between the bootstrap step and any subsequent
`connect`/`run` steps (use a shared volume or artifact cache if needed).

`KEYLATCH_PASSPHRASE` has **no effect** on the `file` backend. The passphrase
env var is not read during bootstrap or credential access (S-FIND-12).

## On-disk layout

```
~/.keylatch/
├── vault/                        # credential store root (0700)
│   └── default/                  # namespace
│       └── ai/openrouter/api_key/
│           ├── value.enc          # AEAD ciphertext (0600)
│           ├── value.enc.nonce    # random nonce (0600)
│           └── value.enc.aad      # AAD binding JSON (0600)
├── keyring/
│   ├── keyring.json              # DEK wrapped with platform KEK (0600)
│   └── identity                  # age-env identity (fallback KEK) (0600)
├── config.json                   # backend config (0600)
└── audit.log                     # HMAC-chained audit log (0600)
```

## Diagnostics

```bash
keylatch doctor           # check file backend availability
keylatch doctor --json    # machine-readable output
```

## Security invariants

- **S-INV-1**: plaintext and base64 write paths removed (CRIT-01, EPIC-03).
- **S-INV-11**: path-traversal inputs that escape the vault root are rejected.
- **T-02-01**: `OpenWithKeyring` is the only production path; absent keyring returns exit 8.
- **T-02-02**: `Set` uses AEAD exclusively; the base64 branch is removed.
- **T-02-03**: `SetVersioned`/`GetVersioned` fail closed without a keyring.

## Related

- [Backends overview](index.md)
- [Security model](../security.md)
- [Bootstrap reference](../cli-reference.md)
