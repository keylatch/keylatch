---
title: Gateway as a systemd user service
description: Run the keylatch gateway as a service, configured from the operator config, with the vault key and backend credentials sealed by the service manager.
---

# Running the gateway as a service

`keylatch gateway systemd` manages a user unit, `keylatch-gateway.service`, that runs
`keylatch gateway up`. It is meant for a host that serves a VM or container network: the gateway
starts at boot, listens on the configured address, and opens the vault without a login session.

Settings (listen address, allowed sources, mint connection, proxy listeners) live in the operator
config, not in the unit: the unit only wires the sealed credentials. Changing a setting is a
config edit plus a service restart, never a reinstall. `gateway up` flags override the config for
ad-hoc runs.

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
- `kek.cred` lives in the gateway directory
  (`~/.config/keylatch/gateway` unless `KEYLATCH_GATEWAY_DIR` is set).
- Keep a copy of the identity somewhere safe if you need to recover the vault on another
  machine: a TPM2-bound credential cannot be decrypted elsewhere.

## Configure

Settings are in `~/.config/keylatch/config.json` (the operator config; nothing else is read for
them). Edit them with `keylatch gateway config`:

```bash
keylatch gateway config set --listen 10.0.2.2:7878 --allow-source 10.0.2.0/24 --github-mint github-app
keylatch gateway config get          # effective settings; --json for machines
keylatch gateway status --json       # same, plus nothing secret
```

```json
{
  "gateway": { "service": {
    "listen": "10.0.2.2:7878",
    "allow_source": ["10.0.2.0/24"],
    "github_mint": "github-app"
  } }
}
```

- `listen` must be an IP literal and port; a wildcard, an empty host or a hostname is refused.
  Without it the gateway binds loopback only.
- A non-loopback `listen` needs `allow_source` (CIDRs, canonicalised, IPv4 or IPv6) unless
  `"allow_any_source": true` is set explicitly. The gateway compares the TCP peer address before
  authentication and never reads `X-Forwarded-For`.
- `github_mint` serves `POST /mint/github` for that `github-app` connection and its
  `mint.github_app` policy.
- `gateway up --listen/--allow-source/--github-mint/--proxy-listen` override the config for one run.

## Install

```bash
loginctl enable-linger "$USER"        # start the user manager at boot
keylatch gateway systemd install      # writes the unit; reads settings from the config
systemctl --user enable --now keylatch-gateway.service
keylatch gateway systemd status
```

`install` may also take `--listen`, `--allow-source`, `--allow-any-source` and `--github-mint`
once: they are validated and written to the config (a convenience for `gateway config set`),
never into the unit. The unit's `ExecStart` is `keylatch gateway up` plus the
`--backend-credential` wiring below. `systemctl --user restart keylatch-gateway.service` applies
a config change. `keylatch gateway systemd print` shows the unit without writing anything,
`status` reports the unit, its state, the credentials and whether lingering is on, and
`uninstall` removes the unit but keeps the config and the credentials.

### macOS

`keylatch gateway install` with the same settings flags (`--listen`, `--allow-source`,
`--allow-any-source`, `--github-mint`) writes the settings to the config and installs a
LaunchAgent, `io.keylatch.gateway`, that runs `keylatch gateway up`; it starts at login, not at
boot. macOS has no `systemd-creds`: a `--backend-credential <cred-name>=<ENV_VAR>` secret is read
at start from the login Keychain (service `keylatch-backend`, account `<cred-name>`), stored with
`security add-generic-password -s keylatch-backend -a <cred-name> -w` (the secret is prompted for).
`gateway install` without flags still installs `keylatchd`.

### Windows

No service installer yet. Settings in the config apply to `keylatch gateway up`; run it from a
scheduled task or a service wrapper of your choice, passing `--backend-credential` only where a
credential directory is provided (otherwise set the backend variable in the task's environment).

## Unattended backend access

A backend that needs a secret from its environment cannot be unlocked by a person at 3 a.m.
Seal that secret as a second systemd credential and let `keylatch` export it at start:

```bash
# The secret is read from stdin, so it is not in argv or shell history (Ctrl-D twice to end).
systemd-creds encrypt --user --name=op-sa --with-key=tpm2 - ~/.config/keylatch/gateway/op-sa.cred

keylatch gateway systemd install \
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

## GitHub through the proxy: the sandbox holds no GitHub token

One or more proxy listeners (`connections.<name>.proxy.github[]`) add an intercepting CONNECT
proxy to the gateway process. The sandbox or VM sends git and `gh` traffic for the GitHub hosts
through it. The proxy terminates TLS with its own CA, checks the route, owner and repository,
**removes the caller's `Authorization`** and injects a GitHub App installation token that never
leaves the host. It shares the gateway's vault key, backend credential and audit log, which is why
it runs in the same process and unit.

### How it behaves

- A listener serves one GitHub host (`github.com` by default, `SUBDOMAIN.ghe.com`, or a GitHub
  Enterprise Server hostname) and one or more installations (GitHub accounts) of the connection's
  App. The caller picks the installation with the **Proxy-Authorization user name**, the account
  login; the password is the proxy token. Bearer auth selects the listener's only installation;
  with several it is refused with 407 `installation_required`. An unknown user name is refused
  with 407 `unknown_installation` and audited.
- Each installation has its own repositories, permissions and in-memory token cache. The token is
  minted when first needed, again about 5 minutes before it expires, and once when GitHub answers
  401 (never within 30 seconds of the last mint).
- Hosts and routes:
  - github.com: git on `github.com`, REST and `/graphql` on `api.github.com`, uploads on
    `uploads.github.com`.
  - GHE.com data residency: `SUBDOMAIN.ghe.com`, `api.SUBDOMAIN.ghe.com`,
    `uploads.SUBDOMAIN.ghe.com` (the `api.` form is documented by GitHub; `uploads.` follows it).
  - GitHub Enterprise Server `HOST`: everything on `HOST`; REST under `/api/v3`, GraphQL at
    `/api/graphql`, uploads under `/api/uploads`. The App token is minted at `https://HOST/api/v3`.
  - git paths (`/<owner>/<repo>[.git]/info/refs`, `/git-upload-pack`, `/git-receive-pack`) get
    `Authorization: Basic base64("x-access-token:<token>")`; API hosts get `Bearer <token>`.
- A path that names another owner than the selected installation answers 403
  `{"error":"owner_mismatch"}`; a repository outside its list answers 403
  `repository_not_allowed`; an unsupported route 403 `route_not_allowed`; all before anything is
  sent upstream. GraphQL and uploads use the selected installation's token. `/app`,
  `/installation` and `/applications` are refused, as are encoded or non-canonical paths.
- Redirects from GitHub go back to the caller; the proxy never replays the token elsewhere.
- Callers must come from `allow_source` (checked before authentication) and present the proxy
  token. A non-loopback listener is refused without `allow_source`.
- Every mint is audited (`mint`, `via: proxy`, owner and host) and every denial too. The token is
  never logged.

### Config

```json
{
  "backend": "op",
  "connections": {
    "github-app": {
      "mint": { "github_app": { "max_ttl": 3600 } },
      "proxy": { "github": [
        { "listen": "10.0.2.2:7879", "host": "github.com", "installations": [
          { "owner": "octo", "repositories": ["octo/app", "octo/tools"] },
          { "owner": "otherorg", "repositories": ["otherorg/service"],
            "permissions": { "contents": "write", "pull_requests": "write", "metadata": "read", "actions": "read" } }
        ] }
      ] }
    }
  }
}
```

or with the CLI (an empty `mint.github_app` policy is created when missing):

```bash
keylatch gateway config add-proxy --connection github-app --listen 10.0.2.2:7879 \
  --owner octo --repo app --repo tools
keylatch gateway config add-proxy --connection github-app --listen 10.0.2.2:7879 \
  --owner otherorg --repo service --permission actions=read
keylatch gateway config remove-proxy --listen 10.0.2.2:7879 --owner otherorg   # or the whole listener
```

- `installations[].permissions` is any GitHub App permission name with `read`, `write` or `admin`;
  the App installation is the real ceiling. The default is `contents:write`, `pull_requests:write`,
  `metadata:read`. `administration`, organization-level administrative permissions and any
  `admin` level need `"allow_admin_permissions": true` on that installation.
- The installation's repositories are its allowlist (added to `allow_repos` for the proxy only,
  `POST /mint/github` is unchanged) and its permissions are its ceiling. The connection's
  `mint.github_app` policy must exist and still supplies `deny_owners`, `callers` and `max_ttl`.
- `host` defaults to `github.com`. Repositories are `owner/name` (a bare name is qualified with
  the installation's owner by the CLI). The App connection needs an `installation_<owner>` field
  per account.
- Listeners must have distinct addresses, different from the gateway's. The default for a new
  listener is up to you; 7879 sits next to the gateway's 7878.
- The CA is name-constrained to the union of the configured hosts. Adding a new host later makes
  `keylatch proxy ca print` refuse until you delete `proxy-ca.pem` and `proxy-ca.key` in the
  gateway directory and re-trust the new CA in the guests.

### Mint policy

`POST /mint/github` and `keylatch mint` apply the connection's `mint.github_app` policy. Edit it
with:

```bash
keylatch gateway config set-mint-policy --connection github-app \
  --allow-repo octo/app --allow-repo octo/tools \
  --permission-ceiling contents=write --permission-ceiling pull_requests=write --permission-ceiling metadata=read \
  --max-ttl 1h --caller service --caller host
keylatch gateway config get          # shows the policy; --json for the machine form
```

Only the flags given change; each list flag replaces its list and an empty value clears it
(`--allow-owner`, `--deny-owner` work the same way). Values are validated, the config is written
atomically with mode 0600, and the command prints the restart hint (the gateway reads the policy at
start).

A request for a permission that is not in the ceiling, or above its level, is refused with `403`
and `{"error":"mint_denied","message":"..."}`; so is a repository outside `allow_repos` and
`allow_owners`, or of a `deny_owners` account. When the policy sets no `permission_ceiling` the
default ceiling applies: `contents:write`, `pull_requests:write`, `metadata:read`. Anything else,
including `workflows`, `actions` and the organization-level permissions, needs an explicit
ceiling entry; `administration` is never minted by the gateway whatever the ceiling says.

### Introspection

`keylatch gateway status --json` and `GET /info` on the gateway return the effective settings, with
no tokens, keys, secret file paths or vault references:

```json
{
  "schema": 1,
  "version": "0.9.0",
  "listen": "10.0.2.2:7878",
  "allow_source": ["10.0.2.0/24"],
  "allow_any_source": false,
  "github_mint": "github-app",
  "github_mint_policy": {
    "allow_repos": ["octo/app"], "allow_owners": [], "deny_owners": [],
    "permission_ceiling": {"contents": "write", "pull_requests": "write", "metadata": "read"},
    "callers": ["service", "host"], "max_ttl": 3600
  },
  "proxies": [
    { "listen": "10.0.2.2:7879", "host": "github.com", "connection": "github-app",
      "installations": [
        { "owner": "octo", "repositories": ["octo/app"], "permissions": {"contents": "write", "pull_requests": "write", "metadata": "read"}, "allow_admin_permissions": false }
      ] }
  ],
  "ca": { "sha256": "<hex>", "pem": "-----BEGIN CERTIFICATE-----\n..." }
}
```

`github_mint_policy` is the effective `mint.github_app` policy of the `github_mint` connection (`null`
when there is no such connection or policy): the lists are as configured, `permission_ceiling` and
`callers` show the defaults when the policy sets none, `max_ttl` is in seconds. It was added to
`schema: 1` as a new field; existing readers that ignore unknown fields are unaffected.

`/info` sits behind the source allowlist like every route and also needs a valid gateway session
token (any capability): the reply names repositories and permissions, and every legitimate caller
already holds a token. `ca` is the public certificate only and is absent until the proxy has
created it.

### Owner setup

```bash
loginctl enable-linger "$USER"
# 1. Vault key and backend credential: see the sections above.
# 2. Settings.
keylatch gateway config set --listen 10.0.2.2:7878 --allow-source 10.0.2.0/24 --github-mint github-app
keylatch gateway config add-proxy --connection github-app --listen 10.0.2.2:7879 --owner octo --repo app
# 3. Install and start.
keylatch gateway systemd install --backend-credential op-sa=OP_SERVICE_ACCOUNT_TOKEN:$HOME/.config/keylatch/gateway/op-sa.cred
systemctl --user enable --now keylatch-gateway.service
# 4. Verify.
keylatch gateway systemd status --check-backend
keylatch gateway status --json | head
ss -ltn | grep -E '7878|7879'
keylatch proxy ca print | openssl x509 -noout -subject -ext nameConstraints
```

State files in the gateway directory: `proxy-ca.pem` (public), `proxy-ca.key` (0600),
`proxy-token` (0600, `keylatch proxy token print`). Delete them and restart to rotate; guests must
then trust the new CA. The CA key is a plain 0600 file because an unattended service has no
keyring; the name constraints limit what a stolen key could vouch for.

### Sandbox / VM guest contract

| Item | Value |
|---|---|
| Proxy | `http://<listen>` of the listener (for example `http://10.0.2.2:7879`): plain HTTP to the proxy, CONNECT for HTTPS. |
| Proxy auth | `Proxy-Authorization: Basic base64("<owner>:<token>")`, that is `http://<owner>:<token>@10.0.2.2:7879`: the user name is the GitHub account login, the password is `keylatch proxy token print` from the host (kept in a 0600 file in the guest). Bearer `<token>` selects the only installation when there is exactly one. |
| CA | `keylatch proxy ca print` on the host (PEM, no key), or the `ca.pem` of `GET /info` (check `ca.sha256`). Install it in the guest trust store (for example `/usr/local/share/ca-certificates/keylatch-proxy.crt`, then `update-ca-certificates`) or point git at it with `http.sslCAInfo`. |
| Through the proxy | Every host of the listener (`github.com`, `api.github.com`, `uploads.github.com`, or the Enterprise equivalents); everything else goes direct. |
| git | `https://<host>/<owner>/<repo>.git` with no credential helper. Per owner: `git config --global http.https://github.com/<owner>/.proxy http://<owner>:<token>@<proxy>`. Any placeholder credential is replaced. |
| gh | `GH_TOKEN=<any placeholder>`, `GH_HOST=<host>`, and `HTTPS_PROXY=http://<owner>:<token>@<proxy>` chosen by the repository's owner. |
| Placeholder | git needs no credential in the URL and no credential helper. If a tool insists on one (`https://x-access-token:<placeholder>@github.com/...`), any value works: the proxy strips it. |
| Refused | Another owner's paths (403 `owner_mismatch`), repositories outside the list, administrative permissions unless allowed, unknown users (407). |

The settings below are exactly what the proxy test suite (`internal/proxy/realclients_test.go`)
gives real `git` and `gh` binaries; it clones, commits, pushes a branch (including a push over
1 MiB, which git sends chunked), runs `gh api user`, `gh pr create --draft` and `gh pr view`
against a fake GitHub, and checks that upstream never sees the placeholder or the proxy token:

```bash
# one proxy user per owner; PROXY is the listener address, TOKEN is `keylatch proxy token print`
git config --global http.sslCAInfo /etc/keylatch/proxy-ca.pem
git config --global http.https://github.com/octo/.proxy "http://octo:$TOKEN@$PROXY"
git config --global http.https://github.com/otherorg/.proxy "http://otherorg:$TOKEN@$PROXY"
git config --global credential.helper ''          # no helper; nothing to store
git clone https://github.com/octo/app.git

# gh: the proxy picks the installation from the proxy user, gh needs any token
export GH_TOKEN=placeholder GH_HOST=github.com
export HTTPS_PROXY="http://octo:$TOKEN@$PROXY"
export SSL_CERT_FILE=/etc/keylatch/proxy-ca.pem   # gh is a Go program: SSL_CERT_FILE or the system store
gh pr create --draft --head feature --base main --title "..." --body "..."
```

How the clients behave: curl (so git and gh through `HTTPS_PROXY`) sends the proxy credentials
only after a `407 Proxy Authentication Required` with `Proxy-Authenticate: Basic`, which is what
the proxy answers to a caller with no, an unknown or a wrong credential. Inside the tunnel the
proxy speaks HTTP/1.1 only; clients fall back from HTTP/2 on their own, and the proxy talks
HTTP/2 to GitHub where offered. Refused paths answer `403` with a JSON body; git prints
`The requested URL returned error: 403`. An unknown proxy user fails the tunnel (`CONNECT tunnel
failed, response 407`). Git commands that reach an owner use that owner's `.proxy` entry; a
mismatch (one owner's proxy user asking for another owner's repository) is `owner_mismatch`.

### Risks

- A mint reads three secrets (app id, installation id, key) per installation about once an hour,
  plus start-up reads and one extra set per 401 retry (at most one per 30 seconds). Backend rate
  limits are per account, so give the service account its own vault.
- One process serves the gateway and every proxy listener; if the backend is unreachable at a
  mint, git and API calls answer 503 `credential_unavailable` until it recovers (not retried for
  5 seconds). A bind failure on any address stops the process and the service manager restarts it.
- A token lives in memory for up to an hour and can do whatever its permissions allow on its
  repositories. Anyone who can reach a listener and knows the proxy token can use it: keep the
  token file 0600 and `allow_source` tight. Branch protection stays the merge gate.
- The CA key is a 0600 file on the host, constrained to the configured hosts.
- Exercised with real `git` and `gh` against a local fake GitHub (HTTP/2 upstream, TLS signed by a test CA). Not exercised against real GitHub, GitHub Enterprise Server, GHE.com or TPM2.
