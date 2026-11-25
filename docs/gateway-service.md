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

## 1Password behind the gateway, unattended

With the `op` backend the gateway reads secrets through the `op` CLI. A person signing in
does not work for overnight runs, so give the unit a
[1Password service account](https://developer.1password.com/docs/service-accounts/) that can
read one vault only.

1. In 1Password create a vault (for example `keylatch-agent`), put the GitHub App private key
   in it, and create a service account with read access to that vault only.
2. Seal the service account token for the unit. The token is read from stdin, so it never
   appears in argv or shell history; paste it and press Ctrl-D twice:

   ```bash
   systemd-creds encrypt --user --name=op-sa-token --with-key=tpm2 - \
     ~/.config/keylatch/gateway/op-sa-token.cred
   ```

   `--name=op-sa-token` must match; use `--with-key=host` without a TPM2.
3. Install the unit with the credential:

   ```bash
   keylatch gateway systemd install --listen 192.168.150.1:8788 \
     --allow-source 192.168.150.0/24 --github-mint github-app \
     --op-service-account-credential ~/.config/keylatch/gateway/op-sa-token.cred
   ```

   (use the absolute path; `~` is not expanded inside a unit.) The unit gets
   `LoadCredentialEncrypted=op-sa-token:<file>` and `ExecStart=... --op-service-account-credential op-sa-token`.
   At start `keylatch` reads `$CREDENTIALS_DIRECTORY/op-sa-token` and exports
   `OP_SERVICE_ACCOUNT_TOKEN` in its own process. The token is never in an env file,
   `ExecStart`, or a log line.
4. Verify without printing the token:

   ```bash
   keylatch gateway systemd status --check-op   # decrypts for this call only, runs `op whoami`
   journalctl --user -u keylatch-gateway -n 20  # "gateway: 1Password service account authenticated"
   keylatch doctor                              # backend.op.auth points here when the shell has no token
   ```

Boot start stays the default: with `loginctl enable-linger "$USER"` the unit starts at boot.
A failed `op whoami` at start is logged but does not stop the gateway, so a boot before the
network is up recovers when `op` can reach 1Password again.

## GitHub through the proxy: the VM holds no GitHub token

`--with-proxy --proxy-listen <ip:port>` adds an intercepting CONNECT proxy to the same
unit. The guest sends git and `gh` traffic for `github.com`, `api.github.com` and
`uploads.github.com` through it. The proxy terminates TLS with its own CA, checks the route and
repository, **removes the caller's `Authorization`** and injects a GitHub App installation token
that never leaves the host.

I chose the same unit over a sibling unit: both listeners need the same vault key, the same
1Password service account and the same audit log, so a second unit would duplicate the sealed
credentials and a second process would race on them. The cost is that one crash restarts both;
`Restart=on-failure` covers that. The default proxy port is **8789** (the gateway uses 8788).

### How it behaves

- One installation token is minted for exactly the `repositories` listed, with the configured
  permissions (default `contents:write`, `pull_requests:write`, `metadata:read`; `actions:read`,
  `checks:read` and `issues:write` may be added; `administration` and everything else is refused
  at startup). It is cached in memory, minted again about 5 minutes before it expires, and again
  once when GitHub answers 401 (never more often than every 30 seconds).
- `github.com`: only git smart HTTP (`/<owner>/<repo>[.git]/info/refs`, `/git-upload-pack`,
  `/git-receive-pack`) with `Authorization: Basic base64("x-access-token:<token>")`.
- `api.github.com` (REST and `/graphql`) and `uploads.github.com`: `Authorization: Bearer <token>`.
  `/app`, `/installation` and `/applications` are refused so the cached token cannot be revoked.
- A repository path outside the list answers `403 {"error":"repository_not_allowed"}` before
  anything is sent to GitHub; an unsupported route answers `403 {"error":"route_not_allowed"}`.
  Encoded or non-canonical paths are refused.
- Redirects from GitHub go back to the caller; the proxy never replays the token elsewhere.
- Callers must come from `--allow-source` (same check as the gateway, before authentication) and
  present the proxy token. Without `--allow-source` a non-loopback `--proxy-listen` is refused.
- Every mint is audited (`mint`, `via: proxy`) and every denial too. The token is never logged.

### Owner setup (Fedora, normal shell)

Everything in the sections above applies (sealed vault key, 1Password service account). Then:

```bash
# 1. GitHub App private key and ids live in the 1Password vault the service account can read;
#    connect the github-app connection with op:// references (see `keylatch connect github-app`).

# 2. Operator config (~/.config/keylatch/config.json): the mint policy is the ceiling, the proxy
#    block says which repositories the proxy token covers.
```

```json
{
  "backend": "op",
  "connections": {
    "github-app": {
      "mint": { "github_app": {
        "allow_repos": ["octo/app", "octo/tools"],
        "permission_ceiling": { "contents": "write", "pull_requests": "write", "metadata": "read" }
      } },
      "proxy": { "github": {
        "repositories": ["octo/app", "octo/tools"]
      } }
    }
  }
}
```

All repositories must belong to one owner (one installation). Optional `permissions` replaces the
default set; each must also be under the mint ceiling.

```bash
# 3. Install (adds --proxy-listen/--proxy-connection to ExecStart) and start.
keylatch gateway systemd install --listen 192.168.150.1:8788 --allow-source 192.168.150.0/24 \
  --github-mint github-app --with-proxy --proxy-listen 192.168.150.1:8789 \
  --op-service-account-credential ~/.config/keylatch/gateway/op-sa-token.cred
systemctl --user enable --now keylatch-gateway.service

# 4. Verify.
keylatch gateway systemd status --check-op
ss -ltn | grep -E '8788|8789'
keylatch proxy ca print | openssl x509 -noout -subject -ext nameConstraints
keylatch proxy token print > /dev/null && echo token ok      # created on first use, mode 0600
curl -s -o /dev/null -w '%{http_code}\n' --proxy http://192.168.150.1:8789 \
  --proxy-header "Proxy-Authorization: Bearer $(keylatch proxy token print)" \
  --cacert <(keylatch proxy ca print) https://api.github.com/repos/octo/app    # 200
```

State files live in the gateway directory: `proxy-ca.pem` (public), `proxy-ca.key` (0600),
`proxy-token` (0600). Delete them (and restart) to rotate; the guest must then trust the new CA.
The CA key is a plain 0600 file because an unattended unit has no keyring. The certificate is
name-constrained to `github.com`, so even a stolen key cannot vouch for other sites.

### agent-os guest contract

| Item | Value |
|---|---|
| Proxy | `http://192.168.150.1:8789` (plain HTTP to the proxy, CONNECT for HTTPS) |
| Proxy auth | `Proxy-Authorization: Bearer <token>` or Basic with any user and the token as password (`http://keylatch:<token>@192.168.150.1:8789`). The token is `keylatch proxy token print` on the host; the guest keeps it in a 0600 file. |
| CA | `keylatch proxy ca print` on the host (PEM, no key); install into the guest trust store, e.g. `/usr/local/share/ca-certificates/keylatch-proxy.crt` then `update-ca-certificates`; for git alone `http.sslCAInfo`. |
| Through the proxy | `github.com`, `api.github.com`, `uploads.github.com` (set `HTTPS_PROXY`, or per host `git config http.https://github.com/.proxy`). Everything else keeps going direct. |
| git | `https://github.com/<owner>/<repo>.git` URLs; no credential helper and no token. If git insists on a credential, any placeholder works: the proxy replaces it. |
| gh | `GH_TOKEN=placeholder` (any non-empty string) and `GH_HOST=github.com`; `gh` talks to `api.github.com` through `HTTPS_PROXY`. |
| Not available | Repositories outside the list (403), `administration`, merging beyond what the token's permissions and branch protection allow. |

### Risks

- 1Password service account rate limits: a mint reads three items (app id, installation, key),
  roughly 3 reads per hour plus start-up and one extra pair per 401 retry (capped at one per 30
  seconds). That is far under the hourly and daily caps for service accounts, but the caps are
  per account and shared with anything else using it; give this service account its own vault
  and check the plan's limits (`op service-account ratelimit`).
- One process serves both the gateway and the proxy; if the vault or `op` is unreachable at a
  mint, git and API calls answer 503 `credential_unavailable` until it recovers (the failure is
  not retried for 5 seconds).
- The token the proxy holds lives in memory for up to an hour and can do whatever its
  permissions allow on the listed repositories: push branches and open pull requests. Branch
  protection stays the merge gate.
- A guest that can reach the proxy and knows the proxy token can use the token's powers; keep
  the token file 0600 and the source CIDR tight.
