---
title: Quickstart
since: 0.1.0
---

# Quickstart

Get from zero to a working credential injection in five steps.

---

## Step 1 — Install

```bash
brew install keylatch/tap/keylatch
```

Verify the installation:

```bash
keylatch --version
```

Other platforms: binary download, Scoop (Windows), or Docker — see [README.md](../README.md#install).

---

## Step 2 — Bootstrap

```bash
keylatch bootstrap
```

`bootstrap` creates `~/.keylatch/` with mode `0700` and writes a default `config.json`. It initializes the encrypted vault directory (`~/.keylatch/vault/`), generates a salt for key derivation, and verifies the chosen backend is reachable. Safe to run multiple times — it is idempotent.

This step is required. Running `keylatch run` on a machine that has not been bootstrapped exits with code 7 and the message `"keylatch not bootstrapped — run: keylatch bootstrap"`.

**Single-command bootstrap** (CI and scripted environments):

```bash
keylatch bootstrap --backend file   # or: keychain, op, bw
```

**Interactive wizard** (recommended for first-time users):

```bash
keylatch setup
```

The wizard prompts for your storage preference at the start:

```
Store credentials locally (AEAD) or reference from a password manager? [local/reference/q]
```

Choose `local` for AEAD-encrypted local storage, or `reference` to store a URI that resolves at runtime via 1Password (`op://`), AWS Secrets Manager (`aws-sm://`), or HashiCorp Vault (`hashivault://`).

---

## Step 3 — Connect a provider

```bash
# Interactive prompt (recommended — no shell history exposure):
keylatch connect openrouter

# Or via stdin (CI-safe):
printf '%s' "$OPENROUTER_API_KEY" | keylatch connect openrouter -f api_key=@-
```

This stores your key under the encrypted path `default/ai/openrouter/api_key` in your configured backend. The value is AEAD-encrypted before write — it is never persisted in plaintext. Keylatch reads the `openrouter` provider template to know which fields to expect and how to inject them.

To see all available providers:

```bash
keylatch registry list
```

---

## Step 4 — Run a command with credential injection

```bash
keylatch run openrouter -- echo hello
```

Keylatch retrieves the stored API key from the backend, injects it as `OPENROUTER_API_KEY` into the subprocess environment, and executes `echo hello`. The key is never echoed to stdout, stderr, or logs.

The default runtime mode is `gateway_typed`, which routes through the local gateway. If the gateway is not running, start it first:

```bash
keylatch gateway up --detach
```

For a mode that does not require the gateway, use `direct_brokered`:

```bash
keylatch run openrouter --runtime direct_brokered -- echo hello
```

See [Runtime Modes](architecture/modes.md) for the full five-mode explanation and when to use each.

---

## Step 5 — Verify your setup

```bash
keylatch doctor
```

`doctor` prints four sections:

| Section | What it checks |
|---------|----------------|
| **Environment** | `KEYLATCH_BACKEND`, config path, vault directory permissions |
| **Daemon** | Whether `keylatchd` / the gateway process is running |
| **Backends** | Reachability and authentication state for the configured backend |
| **Providers** | Registered provider templates and connection status |

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | All checks passed |
| `1` | One or more warnings (non-fatal) |
| `2` | One or more critical failures |

Use `keylatch doctor --json` for machine-readable output.

---

## What's next

- [Gateway setup](getting-started.md#gateway) — start and manage the local credential gateway
- [Agent setup](getting-started.md#agent-setup) — write agent profiles for Claude Code and others
- [Runtime modes](architecture/modes.md) — understand `gateway_typed`, `gateway_sdk`, `direct_brokered`, and more
- [Provider catalog](providers/index.md) — all 35 supported providers with connect examples
