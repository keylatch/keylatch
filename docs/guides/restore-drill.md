---
title: Import secrets and rehearse recovery
description: Inventory the secrets on a machine, import them into a backend with a keyed-hash manifest, and prove on a fresh host that every item can be restored.
---

# Import secrets and rehearse recovery

A backup you have never restored is a hope. This guide moves the secrets that sit in `.env` files, the OS keychain, `gh` and a password manager into one backend, records a manifest that proves what each item held, and shows how to check the backend against that manifest from a clean host.

Nothing in the inventory, the plan, the manifest or the drill report contains a value.

## 1. Inventory

Write a map of where to look:

```yaml
version: 1
collections:
  apps: Work/apps          # namespace -> backend collection
sources:
  - {type: env-file, namespace: apps, glob: "~/code/*/.env*"}
  - {type: secret-service, namespace: personal, service: login}
  - {type: keychain, namespace: personal, service: login, accounts: [deploy]}
  - {type: gh, namespace: github}
  - {type: password-manager, namespace: personal, manager: bw, items: ["Cloudflare API"]}
```

```bash
keylatch migrate inventory --map map.yaml --out plan.json
```

`plan.json` lists a name, a source reference and a target path per item. Edit it to drop what you do not want moved. The map and plan formats are in `schemas/migrate-map.schema.json` and `schemas/migrate-plan.schema.json`.

## 2. Import

```bash
keylatch migrate import --plan plan.json --to bw --dry-run
keylatch migrate import --plan plan.json --to bw --manifest-out manifest.json
```

The import asks for your presence, then reads each value from its source and writes it to the backend (`bw`, `op` or the system `broker`). It is idempotent: an item whose stored value already equals its source is left alone. `--dry-run` reads and compares but writes nothing and needs no presence.

`--manifest-out` asks for a recovery passphrase (or reads one line from standard input with `--passphrase-stdin`) and records `HMAC-SHA256(key, value)` for every item, where `key` comes from the passphrase through Argon2id with a random salt kept in the manifest. The manifest alone cannot be used to recover a value, and without the passphrase nobody can recompute a hash to check a guess. Keep the passphrase somewhere other than the backend.

With `--to broker` the daemon stores every item in one request after one presence prompt and answers with a keyed hash per value, which Keylatch compares with its own. The broker never returns a value, so an item it already holds is skipped rather than compared; change one with `keylatch set`.

## 3. Verify

```bash
keylatch migrate verify --manifest manifest.json
```

prints `{"ok": <count>, "failed": [...], "missing": [...], "duration": "..."}` and exits non-zero when any item differs or is absent.

## 4. Drill on a fresh host

On a host that has only the backend configured (a new account, a new laptop, a CI runner):

```bash
keylatch drill restore --manifest manifest.json --report /dev/stdout
```

The drill fetches every manifest item, compares keyed hashes and writes the same report. `ok` equals the item count when everything restores; a deleted item appears under `missing`, an altered one under `failed`. Run the drill on a schedule, or after any backend migration, and treat a non-zero exit as an incident.

The system broker is not a drill target: it never returns values, and its adopt check already covers its store.
