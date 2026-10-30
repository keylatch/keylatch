---
title: Sync deploy secrets
description: Keep Vercel environment variables, GitHub Actions secrets and local env files in step with the connections they come from, without pasting a value anywhere.
---

# Sync deploy secrets

Deploy secrets usually live in three places at once: the secret manager, a Vercel project and a GitHub repository, plus a `.env.local` on your machine. Keeping them equal by hand means pasting values into dashboards and shells, and nothing tells you when one of them drifts. `keylatch sync` declares the mapping once, in `keylatch.sync.yaml` at the repository root, and does the copying.

The guarantee is the point: the **daemon** reads each value and sends it to the target. The value never crosses the control socket, your shell, the CLI's arguments or an agent session's environment. `keylatch sync apply` and `keylatch sync rotate` therefore need the [system broker](broker-linux.md); the read-only commands also work without it.

## The manifest

```yaml
version: 1
targets:
  web:   {type: vercel, project: prj_example, team: team_example, credential: vercel-deploy}  # or link: .vercel/project.json
  ci:    {type: github-actions, repo: owner/app, environments: [production], credential: github-app-ci}
  local: {type: env-file, path: .env.local}
vars:
  - name: DATABASE_URL
    from: {connection: app-db, field: url}
    sensitive: true            # Vercel type "sensitive"; the default
    to: {web: [production, preview], ci: [repository, production], local: [file]}
```

The shipped example is `examples/keylatch.sync.yaml`; the schema is `schemas/sync.schema.json`.

- **`credential`** names the Keylatch connection the daemon uses for the target's API. A connection is found by its stored path: `<name>`, `<name>/<field>`, or the one stored path ending in `/<name>/<field>`; two matches are an error, never a guess. For GitHub, a GitHub App connection is better than a personal token: `keylatch doctor` warns while a target is reached with a long-lived token.
- **`from`** names the connection and field the value comes from.
- **`link`** reads the project id (and team) from `.vercel/project.json`.
- **Environments** are `production`, `preview` and `development` for Vercel, `repository` plus the environments you list for GitHub, and `file` for an env file.

`keylatch sync check` validates the file without any network access. A violation fails with the key path, for example `vars[0].to.web[0]`. The rules:

| Rule | Why |
|---|---|
| No unknown keys, targets or environments | Typos fail instead of syncing nothing. |
| A sensitive variable cannot go to Vercel `development` | Vercel stores sensitive values for production and preview only; set `sensitive: false` for development. |
| GitHub secret names are upper case and do not start with `GITHUB_` | GitHub refuses them. |
| A name is declared once per target and environment | Two sources for one variable would fight. |
| An env-file path is relative, inside the repository, ignored by git and not tracked | A file that holds secrets must never be committed. |

## See the difference

```bash
keylatch sync diff
keylatch sync diff --prune --json
keylatch sync drift
```

`diff` is the dry run of `apply`. It prints a kind (`add`, `update`, `extra`), the target, the environment, the name and a reason, never a value. The reasons are `missing`, `changed source value`, `changed environments`, `changed Vercel type`, `changed outside keylatch` and `not written by keylatch`.

A changed source value is found without comparing values anywhere outside the daemon: after each write the daemon stores a keyed hash of the value (`HMAC-SHA256` under a key only the daemon holds) and compares the source's current hash with it. A target edited by someone else after the last sync has a newer update time than the daemon recorded and shows as `changed outside keylatch`.

`drift` reports missing, extra and differing names **without reading any value** and exits 1 when anything differs. Agent sessions may run `check`, `diff` and `drift`: nothing they print contains a value. Without the broker, `drift` and `diff` run in your terminal against the configured backend for the target credentials, and compare names, environments and types only.

Entries Keylatch does not manage are listed by Vercel but never touched: variables tied to a git branch, a custom environment or an integration. GitHub organization secrets are out of scope.

## Apply

```bash
keylatch sync apply
keylatch sync apply --prune
```

`apply` needs your presence. The prompt lists the counts per target and the names, never a value; `--prune`, which also deletes the names the manifest does not list, is called out separately. It writes only what differs, so a second run writes nothing, and it records one audit event per write (`sync.write`, `sync.delete`) with the connection, target, environment, name, caller kind and the digest of the approved request. No event holds a value or a hash of one.

- **Vercel** entries are written with `POST /v10/projects/{id}/env?upsert=true` as type `sensitive` or `encrypted`. A change of environments or type writes the new entry first and deletes the old one afterwards.
- **GitHub** secrets are sealed to the repository's public key (an anonymous sealed box) before they leave the daemon, with the key id GitHub returned.
- **Env files** are written by the daemon through file descriptors this command passes: the existing file opened read-only and a new `0600` file in the same directory. The daemon writes the merged content, keeping lines that are not managed variables, and calls `fsync`; the command then renames the new file over the old one. The value never enters the CLI process.

An agent session that runs `apply` or `rotate` is refused before anything is read, with the command for a human to run.

## Rotate

```bash
keylatch sync rotate DATABASE_URL
keylatch sync rotate DATABASE_URL --target web --keep-old 10m
```

Change the value at its provider and store the new value in the source connection first. Then `rotate` (presence required):

1. writes the source's current value to every target of the variable;
2. verifies each target: Vercel `encrypted` entries are read back and compared, write-only stores (Vercel `sensitive`, GitHub) are checked by the update time they report, and a variable's optional `verify: {url: https://...}` makes the daemon send an HTTPS request with the new value as a bearer token and expect a 2xx;
3. on write or verification failure attempts to restore and verify the previous value (`sync.rotate.rollback`);
4. after all declared remote targets have recorded the current value, persists an encrypted retirement job. The daemon retires the preceding backend version after `--keep-old` (up to 24 hours), then records completion (`sync.rotate.complete`). Pending jobs survive daemon restart and retry failed retirement or audit writes. Retirement failures do not roll back verified destinations.

`retirement-pending` means the new value was verified but the previous backend version is still retained. A `--target` subset cannot retire history while another declared destination has not recorded the new value. Env-file destinations also remain pending: the CLI commits the verified temporary file after the broker responds, and final-file acknowledgement is not yet implemented. Provider-side credential revocation remains manual; backend retirement alone does not invalidate a credential at its provider.

The broker reads the current and immediately preceding stored versions together. Rollback restores that preceding version, even if it was never synced. If the source has no history, `rotate` refuses unless you pass `--no-rollback`. Corrupt history is always refused. Sync no longer creates separate copies of previously applied values; existing `.sync/previous` records are not used for rollback. Revoking the old credential at its provider stays a step you do there.

## Run drift in CI

```bash
keylatch sync check
keylatch sync drift --json
```

`drift` exits 1 on any difference, so a job fails when a target was edited by hand. It needs the daemon for the target credentials, so run it where the broker is installed (a self-hosted runner), or in a terminal. `keylatch doctor` reports the same drift for the repository it runs in, and warns for an env-file target whose name the agent guard does not recognise as a secrets file (use `.env`, `.env.<name>` or `<name>.env`).
