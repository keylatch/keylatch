---
title: Gateway as a systemd user service
description: Run the keylatch gateway at boot on Linux, bound to a bridge address, with the vault key sealed by systemd.
---

# Gateway as a systemd user service

`keylatch gateway systemd` manages a user unit, `keylatch-gateway.service`, that runs
`keylatch gateway up`. It is meant for a host that serves a VM bridge: the gateway starts at
boot, listens on one configured address, and opens the vault without a login session.

## How the vault opens without a login

The `file` backend normally keeps its vault identity in the desktop keyring, which needs a
logged-in session. The unit instead loads the identity as an encrypted systemd credential
(`LoadCredentialEncrypted=`). systemd decrypts it for this service only, into a read-only
file on a ramfs, and the unit points `KEYLATCH_AGE_IDENTITY` at it. The plaintext key is
never written to the disk; `--insecure-file-kek` is not used.

Create the credential once, before bootstrapping the vault:

```bash
umask 077
head -c 32 /dev/urandom > "$XDG_RUNTIME_DIR/kek"
systemd-creds encrypt --user --name=kek --with-key=tpm2 \
  "$XDG_RUNTIME_DIR/kek" ~/.config/keylatch/gateway/kek.cred
KEYLATCH_AGE_IDENTITY="$XDG_RUNTIME_DIR/kek" keylatch bootstrap
shred -u "$XDG_RUNTIME_DIR/kek"
```

- `--with-key=tpm2` binds the credential to the machine's TPM2. Use `--with-key=host` on
  hosts without one: the credential is then bound to `/var/lib/systemd/credential.secret`,
  readable by root. `--user` scopes it to your account and needs systemd 256 or newer.
- The runtime directory is a tmpfs, so the plaintext exists only until `shred`.
- The unit's `systemd.env` and `kek.cred` live in the gateway directory
  (`~/.config/keylatch/gateway` unless `KEYLATCH_GATEWAY_DIR` is set).
- Keep a copy of the identity somewhere safe if you need to recover the vault on another
  machine: a TPM2-bound credential cannot be decrypted elsewhere.

## Install

```bash
loginctl enable-linger "$USER"        # start the user manager at boot
keylatch gateway systemd install --listen 10.0.2.2:7878 \
  --allow-source 10.0.2.0/24 --github-mint github-app
systemctl --user enable --now keylatch-gateway.service
keylatch gateway systemd status
```

`install` writes the unit to `~/.config/systemd/user/` and the environment file, then runs
`daemon-reload`; `--now` also enables and starts it. `keylatch gateway systemd print`
shows the unit without writing anything, `status` reports the unit, its state, the
credential and whether lingering is on, and `uninstall` removes the unit but keeps the
environment file and the credential.

`--listen` is required and must be an IP address and port. A wildcard (`0.0.0.0`, `::`), an
empty host or a hostname is refused, so the gateway cannot end up on every interface. The
address lives in `systemd.env` as `KEYLATCH_GATEWAY_LISTEN`; edit it and restart
the unit to move the gateway.

## Restricting callers by source address

`--allow-source <CIDR>` (repeatable, IPv4 or IPv6) is written into the unit's `ExecStart`
as `--allow-source <CIDR>`, in canonical form (`10.0.2.7/24` becomes
`10.0.2.0/24`), for example:

```
ExecStart=/usr/local/bin/keylatch gateway up --allow-source 10.0.2.0/24 --github-mint github-app
```

The gateway compares the TCP peer address with the CIDRs before authentication and never
reads `X-Forwarded-For`. With a non-loopback `--listen`, `install` and `print` refuse to
continue without `--allow-source`, unless you pass `--allow-any-source` to accept any caller
that can reach the address (it cannot be combined with `--allow-source`).

`--github-mint <connection>` adds `--github-mint <connection>` so the gateway serves
`POST /mint/github` for that `github-app` connection and its `mint.github_app` policy.

## Unattended backend access

A backend that needs a secret from its environment cannot be unlocked by a person at 3 a.m.
Seal that secret as a second systemd credential and let `keylatch` export it at start:

```bash
# The secret is read from stdin, so it is not in argv or shell history (Ctrl-D twice to end).
systemd-creds encrypt --user --name=op-sa --with-key=tpm2 - ~/.config/keylatch/gateway/op-sa.cred

keylatch gateway systemd install --listen 10.0.2.2:7878 --allow-source 10.0.2.0/24 \
  --backend-credential op-sa=OP_SERVICE_ACCOUNT_TOKEN:$HOME/.config/keylatch/gateway/op-sa.cred
```

`--backend-credential <cred-name>=<ENV_VAR>:<file.cred>` is repeatable. The unit gets
`LoadCredentialEncrypted=<cred-name>:<file>`, and `ExecStart` carries only
`--backend-credential <cred-name>=<ENV_VAR>`. At start `gateway up` reads
`$CREDENTIALS_DIRECTORY/<cred-name>` and sets `ENV_VAR` in its own process; the value is never in
an env file, `ExecStart` or a log line. `--name` must match `<cred-name>`.

`ENV_VAR` must be a variable a backend reads a secret from: `OP_SERVICE_ACCOUNT_TOKEN`,
`OP_CONNECT_TOKEN`, `KEYLATCH_OP_CONNECT_TOKEN`, `BW_SESSION`, `VAULT_TOKEN`,
`KEYLATCH_VAULT_TOKEN`, `KEYLATCH_VAULT_SECRET_ID`, `AWS_SECRET_ACCESS_KEY`,
`KEYLATCH_AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `KEYLATCH_AZURE_CLIENT_SECRET`,
`KEYLATCH_GCP_CREDENTIALS_JSON`, `DOPPLER_TOKEN`, `KEYLATCH_DOPPLER_TOKEN`,
`INFISICAL_CLIENT_SECRET`, `KEYLATCH_INFISICAL_CLIENT_SECRET`. Anything else is refused, so the
flag cannot set `PATH`, `LD_PRELOAD` and the like. Non-secret settings (vault address, project)
stay in the config file or `systemd.env`.

For 1Password, create a vault, a service account with read access to that vault only, and seal
its token as above. Verify without printing the secret:

```bash
keylatch gateway systemd status --check-backend   # decrypts for this call only; `op whoami` for 1Password
journalctl --user -u keylatch-gateway -n 20       # "gateway: backend credential op-sa: service account authenticated"
keylatch doctor                                   # backend.op.auth points here when the shell has no token
```

Backends other than 1Password get a decrypt-only verdict. A failed check at start is logged but
does not stop the gateway, so a boot before the network is up recovers on its own. Boot start
stays the default with `loginctl enable-linger "$USER"`.
