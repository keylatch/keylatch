---
title: Moving off the file backend
since: 1.0.0
---

# Moving off the file backend

Keylatch sits between a password manager and an agent. It is not a password manager, so its own encrypted `file` store is not a supported backend. Only `op` (1Password CLI) and `bw` (Bitwarden CLI, including Vaultwarden) are.

If your `config.json` already says `backend: file` (or another unsupported backend), commands now stop with:

```
backend "file" is not supported (unavailable). Supported managers: bw, op. To keep using it for now, set KEYLATCH_ALLOW_UNSUPPORTED_BACKEND=file; to move off it, see docs/backends/moving-off-file.md
```

Nothing is deleted. Your vault stays where it is. The message names the backend and says whether the opt-in applies to it; `keychain`, `op-connect`, `keeper` and `proton-pass` say they cannot be enabled and link to [backends that cannot be enabled](#backends-that-cannot-be-enabled).

## Keep using it for now

Name the backend in the opt-in variable in the environment of every Keylatch process, including the gateway service:

```bash
export KEYLATCH_ALLOW_UNSUPPORTED_BACKEND=file
```

The value is a comma-separated list of backend names. It works only for backends the manifest marks as opt-in (`file`, `lastpass`, `vault`, `aws-sm`, `gcp-sm`, `azure-kv`, `doppler`, `infisical`, `bws`, `sops`); `keychain`, `proton-pass`, `keeper` and `op-connect` stay refused whatever the environment says. `keylatch gateway systemd install|print` and `keylatch gateway install` copy the opt-in from the environment they run in into the unit (`Environment=`) or the LaunchAgent (`EnvironmentVariables`), so the gateway service keeps opening the backend after an upgrade. Set the variable when you run them, and reinstall the service on an existing install. The keylatchd LaunchAgent that `keylatch gateway install` writes without flags does the same. Each process prints one notice to stderr saying what is unproven. `keylatch doctor` reports the backend as a warning while the opt-in is on and as a failure without it. Agent sessions never inherit the variable (`KEYLATCH_*` variables are stripped from child environments).

## Move to `op` or `bw`

No command copies values out of the file vault: `keylatch get` does not print raw values, by design. Move connections by connecting them again against the manager.

1. With the opt-in still set, list what you have:

   ```bash
   keylatch list
   ```

2. Sign in to the manager (`op signin`, or `bw login` then `keylatch bw unlock`).

3. Pick the manager. Nothing migrates when the backend changes: connections stored in `file` stop being visible until you switch back.

   ```bash
   keylatch setup --backend op      # or: --backend bw
   ```

4. Connect each provider again. Either keep the secret in the manager and let Keylatch resolve it, or supply the value from the provider's own console:

   ```bash
   keylatch connect github --provider-ref token=op://Keylatch/github/token
   printf '%s' "$KEY" | keylatch connect openrouter api_key=@-
   ```

   `keylatch migrate inventory` and `keylatch migrate import --to op|bw` move secrets that still sit in `.env` files, the Secret Service, the macOS keychain, `gh` or another password manager.

5. Check the result, then run `keylatch doctor`:

   ```bash
   keylatch list
   keylatch migrate verify --manifest <manifest.json>   # when you wrote one with --manifest-out
   ```

6. Once every connection works on the new backend, unset `KEYLATCH_ALLOW_UNSUPPORTED_BACKEND`. The old vault under `~/.keylatch/vault/` is left untouched; remove it yourself when you no longer need it.

`keylatch migrate cipher` and `keylatch keys rewrap` work on an existing file vault whether or not the opt-in is set.

## Other opt-in backends

`vault`, `aws-sm`, `gcp-sm`, `azure-kv`, `doppler`, `infisical`, `bws`, `sops` and `lastpass` are not password managers Keylatch supports. They keep working as a configured backend while `KEYLATCH_ALLOW_UNSUPPORTED_BACKEND` names them, as described above. To move off one, connect the provider again against `op` or `bw` (steps above). To keep the secret where it is, store only a reference: `keylatch connect <provider> --provider-ref <field>=aws-sm://...` or `hashivault://...` resolves it at use time without making that store the backend; see [external references](external-references.md).

## Backends that cannot be enabled

`keychain`, `op-connect`, `keeper` and `proton-pass` are refused outright: no environment variable or config value turns them on, and a service that still names one stops at start with the message above. Nothing in your old store is deleted.

1. Switch the backend: `keylatch setup --backend op` (or `--backend bw`), after `op signin` or `bw login` and `keylatch bw unlock`.
2. Connect each provider again from the provider's console or from a manager reference:

   ```bash
   printf '%s' "$KEY" | keylatch connect openrouter api_key=@-
   keylatch connect github --provider-ref token=op://Keylatch/github/token
   ```

   `keylatch migrate inventory` and `keylatch migrate import --to op|bw` move secrets that still sit in `.env` files, the Secret Service, the macOS keychain, `gh` or another password manager.
3. Reinstall the gateway service so its unit no longer refers to the old backend, then run `keylatch doctor`.
