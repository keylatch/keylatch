---
title: CI Integration
description: GitHub Actions and GitLab CI integration patterns for Keylatch.
---

# CI Integration

In CI, point Keylatch at an external credential store with a service account. No vault file is stored in the CI system and no passphrase is needed.

## Prerequisites

1. A service account for the store: `OP_SERVICE_ACCOUNT_TOKEN` for 1Password, or `BW_SESSION` for Bitwarden. Store it as a masked CI secret.
2. The credential already lives in that store. CI only references it.
3. The release tarball for your runner from [GitHub Releases](https://github.com/keylatch/keylatch/releases). See [Installation](../installation.md) and [Verifying releases](../verifying-releases.md).

The `file` backend needs an OS keyring, or `--insecure-file-kek`, which keeps the vault key in a plaintext file readable by every process on the runner. Prefer an external store.

---

## GitHub Actions

See [examples/ci/github-actions.yml](examples/ci/github-actions.yml) for the complete workflow.

```yaml
steps:
  - name: Bootstrap Keylatch (1Password)
    run: keylatch bootstrap --backend op
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}

  - name: Connect the provider by reference
    run: keylatch connect openrouter --non-interactive --provider-ref api_key=op://CI/OpenRouter/api_key
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}

  - name: Run script with credentials
    run: keylatch run --clean-env --runtime gateway_typed openrouter -- python3 my_script.py
    env:
      OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}
```

`keylatch run` never prints the raw credential to stdout or logs.

---

## GitLab CI

See [examples/ci/gitlab-ci.yml](examples/ci/gitlab-ci.yml) for the complete pipeline.

```yaml
run_with_credentials:
  script:
    - keylatch bootstrap --backend op
    - keylatch connect openrouter --non-interactive --provider-ref api_key=op://CI/OpenRouter/api_key
    - keylatch run --clean-env --runtime gateway_typed openrouter -- python3 my_script.py
  # OP_SERVICE_ACCOUNT_TOKEN is a masked CI/CD variable
```

---

## Security notes

- Mark the service account token as masked and protected. Never commit it.
- `--clean-env` stops host CI environment variables from reaching the child process.
- A job that can run arbitrary code can read anything the runner can read. Scope the service account to the one vault the job needs.

---

## Related

- [docs/integration/README.md](README.md) — integration guide index
- [docs/cli/environment.md](../cli/environment.md) — all KEYLATCH_* env vars
- [docs/scripting.md](../scripting.md) — scripting patterns
