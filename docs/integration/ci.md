---
title: CI Integration
description: GitHub Actions and GitLab CI integration patterns for Keylatch.
---

# CI Integration

This guide covers using Keylatch in CI/CD pipelines. In CI, Keylatch reads credentials from the vault file (stored as a CI secret) rather than from an interactive backend.

## Prerequisites

1. Run Keylatch locally with the `file` backend to create an encrypted vault:

   ```bash
   KEYLATCH_BACKEND=file keylatch setup
   keylatch connect openrouter
   ```

2. The vault file is at `~/.keylatch/vault/vault.age` (or the path reported by `keylatch doctor`).
3. Store the entire vault file as a CI secret (e.g. `KEYLATCH_VAULT_B64` — base64-encoded).
4. Store the Keylatch vault passphrase as a separate CI secret (e.g. `KEYLATCH_VAULT_PASS`).

---

## GitHub Actions

### Full workflow example

See [docs/integration/examples/ci/github-actions.yml](examples/ci/github-actions.yml) for the complete workflow.

**Key steps:**

```yaml
steps:
  - name: Install Keylatch
    run: |
      curl -sSfL https://keylatch.dev/install.sh | sh
      echo "${HOME}/.keylatch/bin" >> "$GITHUB_PATH"

  - name: Restore vault from secret
    run: |
      echo "${{ secrets.KEYLATCH_VAULT_B64 }}" | base64 -d > /tmp/ci-vault.age
    env:
      KEYLATCH_VAULT_B64: ${{ secrets.KEYLATCH_VAULT_B64 }}

  - name: Bootstrap Keylatch (file backend)
    run: |
      keylatch bootstrap \
        --backend=file \
        --non-interactive
    env:
      KEYLATCH_BACKEND: file
      KEYLATCH_VAULT_PATH: /tmp/ci-vault.age
      KEYLATCH_VAULT_PASS: ${{ secrets.KEYLATCH_VAULT_PASS }}

  - name: Run script with credentials
    run: |
      keylatch run --clean-env --runtime gateway_typed openrouter -- python3 my_script.py
    env:
      KEYLATCH_BACKEND: file
      KEYLATCH_VAULT_PATH: /tmp/ci-vault.age
      KEYLATCH_VAULT_PASS: ${{ secrets.KEYLATCH_VAULT_PASS }}
```

### Log masking

GitHub Actions masks values that match registered secrets automatically. For extra safety, add `::add-mask::` before using a keylatch-derived value:

```yaml
- name: Fetch and mask gateway token
  run: |
    # Fetch the gateway token and mask it from logs
    TOKEN=$(keylatch run --dry-run --json openrouter -- true | python3 -c \
      "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))")
    echo "::add-mask::${TOKEN}"
  env:
    KEYLATCH_BACKEND: file
    KEYLATCH_VAULT_PATH: /tmp/ci-vault.age
```

Note: `keylatch run` itself never prints the raw credential to stdout or logs. `::add-mask::` is for the gateway token only.

---

## GitLab CI

### Full pipeline example

See [docs/integration/examples/ci/gitlab-ci.yml](examples/ci/gitlab-ci.yml) for the complete pipeline.

**Key steps:**

```yaml
variables:
  KEYLATCH_BACKEND: file
  KEYLATCH_VAULT_PATH: /tmp/ci-vault.age

install_keylatch:
  script:
    - curl -sSfL https://keylatch.dev/install.sh | sh

restore_vault:
  script:
    - echo "$KEYLATCH_VAULT_B64" | base64 -d > "${KEYLATCH_VAULT_PATH}"
  # KEYLATCH_VAULT_B64 and KEYLATCH_VAULT_PASS are CI/CD variables (masked)

run_with_credentials:
  script:
    - keylatch bootstrap --backend=file --non-interactive
    - keylatch run --clean-env --runtime gateway_typed openrouter -- python3 my_script.py
```

### Log masking in GitLab CI

GitLab CI masks variables marked as "Masked" in the CI/CD settings. For gateway tokens:

```yaml
mask_gateway_token:
  script: |
    # The gateway token is short-lived — it is masked automatically if set as a CI var.
    # Use keylatch run as the outer wrapper; do not extract and log the token.
    keylatch run --clean-env openrouter -- python3 my_script.py
```

---

## Security notes

- Store the vault file as a CI secret (base64-encoded). Never commit it to the repository.
- Store the vault passphrase as a masked CI secret.
- Use the `file` backend in CI — `keychain` and `op` require interactive auth.
- `--clean-env` prevents host CI environment variables from leaking into child processes.
- The vault file is decrypted in memory at runtime — no plaintext is written to disk.

---

## Related

- [docs/integration/README.md](README.md) — integration guide index
- [docs/cli/environment.md](../cli/environment.md) — all KEYLATCH_* env vars
- [docs/scripting.md](../scripting.md) — scripting patterns
