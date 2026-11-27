# Custom secrets

A custom secret lets the gateway call any HTTPS API with a key you hold, without
writing a provider template or rebuilding keylatch. It is three things: the value
(or an `op://`, `aws-sm://` or `hashivault://` reference to it), the hosts and
paths it may be sent to, and how it is injected into the request.

Custom secrets are defined with commands only. Keylatch does not load template
files from disk.

## Commands

```bash
# Value from stdin (never as an argument)
printf '%s' "$ACME_KEY" | keylatch secret add acme --value-stdin \
  --host api.acme.example --path /v1 --method GET --method POST \
  --header "Authorization: Bearer {value}" --base-url-env ACME_BASE_URL

# Reference kept in a password manager; keylatch stores only the reference
keylatch secret add acme --ref op://Private/acme/key \
  --host api.acme.example --query api_key

keylatch secret list              # name, hosts, injection kind, source (stored or reference scheme)
keylatch secret show acme         # rules only, never the value
keylatch secret add acme --replace ...   # change the rules and/or rotate the value or reference
keylatch secret rm acme           # removes the rules and the stored value
keylatch secret approve acme      # owner: activate what an agent session proposed
keylatch secret reject acme       # owner: discard it
```

| Flag | Meaning |
|------|---------|
| `--value-stdin` / `--ref <uri>` | Exactly one. The value comes from stdin (or a hidden prompt on a terminal); a reference is validated locally and not resolved at add time. |
| `--host <host>` | Allowed upstream host, repeatable. HTTPS only. The first host receives the requests and must be an exact name. A later host may be `*.example.com`. |
| `--path <prefix>` | Allowed upstream path prefix, repeatable. Default `/`. A prefix matches whole segments: `/v1` allows `/v1` and `/v1/x`, not `/v1beta`. |
| `--method <M>` | Allowed HTTP method, repeatable. Default: any. |
| `--header "<Name>: <format>"` | Put the value in a header. `{value}` marks the place, e.g. `Authorization: Bearer {value}` or `X-Api-Key: {value}`. |
| `--query <param>` | Put the value in this query parameter. |
| `--basic <user>` | Send HTTP basic auth with this user name and the value as the password. |
| `--base-url-env <ENV>` | Env var that `keylatch run` sets to the gateway URL for this secret. |

`--replace` changes an existing secret. Give all rule flags again; add `--value-stdin`
or `--ref` to rotate the value, or omit both to keep the stored one. The value is
written before the rules. Without `--replace`, a duplicate name is refused.

Exactly one of `--header`, `--query` and `--basic` is required.

Outside an LLM session `add` takes effect at once: you are the approver. Inside one, `add`
only proposes the secret (see "Agent sessions"). `rm`, `approve` and `reject` are refused
inside an LLM session (exit 2). `list` and `show` are metadata only and work everywhere. `keylatch status` and `keylatch doctor`
list custom secrets by name, hosts, injection kind and source.

## How requests are served

The gateway serves a custom secret at `/sdk/<name>/v1/<path>` and forwards the
request to `https://<first host>/<path>`:

- the path must match an allowed prefix and the method an allowed method, or the
  gateway answers 404 and nothing is sent upstream;
- the caller's `Authorization` header (the gateway session token), `x-keylatch-*`
  headers, cookies and any credential-looking header or query parameter are
  dropped or refused, and the stored credential is injected per the rule;
- redirects are not followed, so the credential cannot be sent to another origin;
  the 3xx response is returned to the caller;
- the upstream host passes the same SSRF check as provider hosts: it must resolve
  to a public address;
- every request writes the usual gateway audit event, with the secret's
  capability (`<name>.request`), host, method and path. The query string and the
  value are never logged.

`keylatch run` sets the `--base-url-env` variable (default `<NAME>_BASE_URL`) to
`http://<gateway>/sdk/<name>/v1`, so an SDK that appends `/chat` reaches
`https://<first host>/chat`. Add any path prefix the API needs to that base URL.
Custom secrets allow no commands by default; pass `--allow <command>` to
`keylatch run`.

Restart the gateway after adding or removing a secret; it reads the rules at start.

## Storage

The value (or reference) is stored in the configured backend at
`default/custom/<name>/value`. The rules are kept in `custom-secrets.json` in the
keylatch config directory (mode 0600); the file never contains the value.

## Validation

- Names are kebab-case (`^[a-z][a-z0-9-]{0,62}$`) and must not match a provider
  template or an existing custom secret.
- Hosts must be DNS names: no IP literals (including decimal and hex forms), no
  `localhost` or private suffixes such as `.local`, `.internal`, `.lan`, no port,
  scheme or path. A `*.` wildcard is only the single leftmost label and is refused
  on public suffixes (`*.com`, `*.co.uk`, `*.github.io`).
- Paths are plain prefixes without `..`, empty segments, query or encoding.
- Header names cannot be `Host`, `Content-Length`, `Cookie` or other framing and
  routing headers.

## Limits

Custom secrets inject one static credential. They do not support OAuth or other
token exchange, request signing (AWS SigV4, HMAC), mTLS or multi-field
credentials. Use a [provider template](./provider-templates.md) for those.

## Agent sessions

An agent in an LLM session may use a custom secret, but only within its rules: the
host, path prefixes and methods set with `secret add`. Anything else gets 404 and
nothing is sent upstream. The agent never sees the value.

An agent may also propose secrets, but they stay unusable until you approve them:

- `keylatch secret add` (and `--replace`) in an LLM session saves the secret as
  *pending*. A pending secret is never routed, and a pending change to an active
  secret leaves the active rules and value serving unchanged. The proposed value or
  reference waits at `default/custom/<name>/pending`, which the gateway never reads.
- `keylatch secret list`, `show`, `status` and `doctor` mark pending entries, and
  `gateway up` logs that a pending secret is skipped.
- `keylatch secret approve <name>` (outside an LLM session, at a terminal) prints what
  will activate: hosts, paths, methods, injection rule, and the reference URI or
  "stored value" (never the value). It then asks for the approver passphrase set with
  `keylatch approve init`, moves the pending value to its active path and activates the
  rules. Restart the gateway afterwards.
- `keylatch secret reject <name>` (same passphrase) deletes the pending value and the
  proposal; a never-approved secret is removed, an active one keeps serving.
- An agent cannot `rm`, `approve` or `reject`.

The usual flow is that you start the agent. Two ways work, and neither needs `--allow`
from inside the session (`keylatch run --allow` is refused in LLM sessions):

- Run the agent under `keylatch run <name> --allow <agent command> -- <agent command>`
  outside an LLM session. The agent gets `--base-url-env` (or `<NAME>_BASE_URL`)
  pointing at `http://<gateway>/sdk/<name>/v1` and a session token granting `<name>.*`.
- Mint a token yourself with `keylatch gateway token create --allow <name>.request`
  and give it to the agent as its gateway token. A token created inside an LLM session
  is marked as one and is still accepted for custom secrets.
