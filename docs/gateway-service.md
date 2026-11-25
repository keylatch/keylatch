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
keylatch gateway systemd install --listen 192.168.150.1:8788 \
  --allow-source 192.168.150.0/24 --github-mint github-app
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
as `--allow-source <CIDR>`, in canonical form (`192.168.150.7/24` becomes
`192.168.150.0/24`), for example:

```
ExecStart=/usr/local/bin/keylatch gateway up --allow-source 192.168.150.0/24 --github-mint github-app
```

The gateway compares the TCP peer address with the CIDRs before authentication and never
reads `X-Forwarded-For`. With a non-loopback `--listen`, `install` and `print` refuse to
continue without `--allow-source`, unless you pass `--allow-any-source` to accept any caller
that can reach the address (it cannot be combined with `--allow-source`).

`--github-mint <connection>` adds `--github-mint <connection>` so the gateway serves
`POST /mint/github` for that `github-app` connection and its `mint.github_app` policy.
