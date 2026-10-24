# Protocol adapters (tier D4)

Some credentials are not HTTP headers: a database password is spoken to a server in the
database's own protocol, and a registry login goes through a helper program. Tier D4 serves them
without giving the child the real value.

## Postgres

```
keylatch run --tier D4 supabase --target db.abc.supabase.co:5432 --db-user app_owner --database prod -- psql
```

The daemon opens an adapter session and the client starts a loopback listener that relays to it.
The child's environment holds only the adapter:

| Variable | Value |
|----------|-------|
| `PGHOST`, `PGPORT` | the loopback listener |
| `PGUSER` | the role named by `--db-user` (default `postgres`) |
| `PGPASSWORD` | the session token, `klph_...` |
| `PGDATABASE` | `--database` (default `postgres`) |
| `PGSSLMODE` | `disable`: the listener is on loopback |
| `DATABASE_URL` | `postgresql://<role>:<token>@127.0.0.1:<port>/<database>?sslmode=disable` |

`PGPASSFILE`, `PGSERVICE`, `PGHOSTADDR`, `PGSSLROOTCERT` and the variables the template names for
the password (for example `SUPABASE_DB_PASSWORD`) are removed, so nothing reaches a database around
the adapter.

The adapter terminates the client's login. The client authenticates with the session token as a
cleartext password over loopback; any other password, including the real one, is refused, and five
wrong attempts end the session's service. It then connects to the target, negotiates TLS and
verifies the server certificate against the system roots, logs in as the role with the stored
password (SCRAM-SHA-256, or cleartext over TLS, as the server asks; MD5 is refused) and relays the rest of the stream.
The password is read from the store for each connection and wiped after the login. A server that
does not offer TLS is refused.

Limits, by design:

- `--target` must match a host the template's `adapter.hosts` lists, and the daemon dials it with
  the same address checks as the placeholder proxy: loopback, private, link-local and metadata
  addresses are refused.
- Replication connections and cancel requests for backends the session did not start are refused.
- The child can run every statement the role allows until the session ends. The role's grants and
  the audit log bound that; the adapter does not parse SQL.
- SCRAM channel binding (`SCRAM-SHA-256-PLUS`) and non-ASCII passwords (SASLprep) are not
  supported upstream. MySQL and the SSH agent adapters are not implemented.

Policy treats D4 like D2 and D3: `enforce.Decide` is asked for runtime `adapter`, a caller that
needs an approval collects one before the session opens, and `run.decided` records the target.
Each adapter connection writes `adapter.connection` with the provider, adapter, host and a reason
(`opened`, `connected`, `bad_token`, `refused`, `upstream_failed`, `cancel`, the close reason);
neither the token nor the password is ever logged.

## Redis and Valkey

Templates can declare `adapter.kind: redis`, a stored password field and exact upstream
`adapter.hosts` entries. Run with `--tier D4 --target cache.example:6379 --db-user app`;
the default ACL user is `default`. The adapter requires verified TLS upstream and accepts a
session token through RESP2 `AUTH` or RESP3 `HELLO ... AUTH`. The client's user name cannot
change the upstream ACL user. After login, the user's ACL permissions bound its commands.

The child receives `REDIS_URL=redis://<user>:<token>@127.0.0.1:<port>`, `REDIS_HOST`,
`REDIS_PORT`, `REDIS_USERNAME`, and the token in `REDISCLI_AUTH` and `VALKEYCLI_AUTH`.
Use `redis-cli -u "$REDIS_URL"` or a client that reads `REDIS_URL`. Ambient Redis credentials
and every injection variable declared by the template are cleared. Inline command login,
unauthenticated connections and a stored password presented to the adapter are refused.
Five incorrect tokens disable authentication for that session; expiry closes active connections.
Upstream AUTH failures are sanitized and never return a server's credential-bearing message.

## Credential helpers

A helper answers a process the agent controls, and the agent can call it itself, so every helper
returns a placeholder bound like a D3 placeholder: for hosts the connection's adapter lists, a
placeholder password the proxy substitutes in flight, and nothing for any other host. One daemon
operation serves both helpers.

| Helper | Template adapter | Child setup |
|--------|------------------|-------------|
| `keylatch git-credential` | `git_credential` | `GIT_CONFIG_*` selects the helper for the adapter's hosts |
| `docker-credential-keylatch` | `docker_credential` | `DOCKER_CONFIG` points at a temporary config with `"credsStore": "keylatch"`, and a wrapper named `docker-credential-keylatch` is first on `PATH` |

`docker-credential-keylatch get` reads a server URL on standard input and prints
`{"ServerURL","Username","Secret"}` with the placeholder as the secret; `store` and `erase` do
nothing and `list` prints `{}`. A registry outside the adapter's hosts, a missing session or a
missing daemon answers `credentials not found in native keychain` and exits 1. The same program is
shipped as its own executable for use outside a Keylatch run. The temporary Docker config replaces
the user's `~/.docker/config.json` for the child, and the wrapper is Unix only.

## Testing

`internal/adapter/postgres` runs the adapter against an in-process fake server that speaks
cleartext and SCRAM-SHA-256 with and without TLS, an MD5 request (refused), and against `psql` when it is installed.
`tests/adapters` (build tag `adapters`) runs `psql`, the Node `pg` client and a generated Prisma
client against a real server. Each child receives only the session token, and its query must
return the stored upstream role. The CI job `adapters` provides the server and Node 26. Without
the server the tests skip and name what is missing; skipped tests provide no conformance evidence.

For a local run, start the declared PostgreSQL service with `infractl dev services up <checkout>`.
Install and generate the Prisma fixture with `npm ci --prefix tests/adapters/prisma` and
`npm run generate --prefix tests/adapters/prisma`. Set `KEYLATCH_TEST_PG_ADDR=127.0.0.1:55432`,
`KEYLATCH_TEST_PG_USER=app_owner`, `KEYLATCH_TEST_PG_PASSWORD=test`,
`KEYLATCH_TEST_PG_DATABASE=appdb` and `KEYLATCH_TEST_NODE_PG` to the absolute
`tests/adapters/prisma/node_modules` path. Run `go test -tags adapters -count=1 ./tests/adapters/...`.
Stop the service with `infractl dev services down <checkout>`; its data is temporary.

The same managed service declaration provides Redis on `127.0.0.1:56379`. Set
`KEYLATCH_TEST_REDIS_ADDR` to that address and `KEYLATCH_TEST_REDIS_PASSWORD=test` to run
the Redis CLI conformance test. It checks RESP2, RESP3, the upstream ACL identity, and refusal
of the stored password at the adapter. Unit tests additionally verify TLS, credential wiping,
bounded frame parsing, failure sanitization and cancellation.
