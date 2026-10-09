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
| Key derivation | KEK derived from a vault identity held in the OS keyring (macOS Keychain or Secret Service); a plaintext identity file only with `--insecure-file-kek` |
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
- `~/.keylatch/keyring/keyring.json` (mode 0600) — wraps the DEK with the KEK
- the vault identity the KEK is derived from, in the OS keyring, plus
  `~/.keylatch/keyring/identity.keyring` (mode 0600), a non-secret reference
  naming the keyring item

### Where the vault identity lives

| Platform | Store |
|----------|-------|
| macOS | login keychain, generic password with service `keylatch-vault-kek` |
| Linux / BSD | Secret Service (GNOME Keyring, KWallet) through `secret-tool`, attributes `application=keylatch`, `purpose=kek` |
| Windows | DPAPI (current user) with a random entropy blob, stored under `%LOCALAPPDATA%\keylatch\kek` |
| Containers, headless hosts, Linux without a Secret Service session | none: bootstrap fails closed unless you opt in with `--insecure-file-kek` |

The secret reaches `security` and `secret-tool` on stdin, never on the command
line. Keylatch never falls back to a plaintext file on its own: without a
reachable store, bootstrap and `keylatch setup --backend file` stop with an
error that names the opt-in. A keyring item is readable by other processes running as your user while
the keyring is unlocked, so this keeps the key off disk and out of backups and
file copies; it is not a boundary against a process running as you.

`keylatch bootstrap --insecure-file-kek` (or `KEYLATCH_INSECURE_FILE_KEK=1`)
writes the identity to `~/.keylatch/keyring/identity` instead. Anything running
as your user can copy that file together with the vault and decrypt every
secret offline. `keylatch doctor` reports it as "plaintext KEK on disk".

### Upgrading an existing install

Installs created before the keyring change have a plaintext
`~/.keylatch/keyring/identity`. The next time the vault is opened (or when you
re-run `keylatch bootstrap`) keylatch copies the identity into the OS keyring,
reads it back to verify it, writes `identity.keyring`, overwrites the file
with random bytes and deletes it.
Secrets do not need to be re-encrypted. If no keyring is reachable the file
keeps working, a warning is printed once per command, and `keylatch doctor`
fails until you either make a keyring available or acknowledge the risk with
`keylatch bootstrap --insecure-file-kek`.

Older keylatch binaries cannot read the keyring item, so after the move they
can no longer open the vault.

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
  run: keylatch bootstrap --insecure-file-kek
  env:
    KEYLATCH_CONFIG_DIR: /tmp/.keylatch

- name: store secret
  run: printf '%s' "$API_KEY" | keylatch connect openrouter api_key=@-
  env:
    KEYLATCH_CONFIG_DIR: /tmp/.keylatch
```

CI runners usually have no OS keyring, so the plaintext identity file is the
KEK source there and must be opted into. The identity file must persist between the bootstrap step and any subsequent
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
│   ├── keyring.json              # DEK wrapped with the KEK (0600)
│   └── identity.keyring          # reference to the OS keyring item (0600)
│                                 # (identity + identity.insecure instead with --insecure-file-kek)
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
