# Vaultwarden E2E fixture (`make test-e2e-bw`)

`internal/backend/bw/bw.go`'s `Open()` hard-requires an `https://` server
URL — Keylatch never bypasses TLS verification, even for a self-hosted
Vaultwarden instance. `docker-compose.vaultwarden.yml` runs Vaultwarden
HTTP-only and puts a Caddy sidecar (`contrib/vaultwarden-e2e/Caddyfile`) in
front of it, terminating TLS with Caddy's `tls internal` self-signed CA, so
the `https://` requirement can be satisfied end-to-end without a real
certificate.

This doc is the fixture's actual runbook — the steps below are not optional
extras, `make test-e2e-bw` will not pass without them.

## 1. Bring the stack up

```bash
docker compose -f docker-compose.vaultwarden.yml up -d
```

Wait for both services to report healthy:

```bash
docker compose -f docker-compose.vaultwarden.yml ps
```

## 2. Find the published Caddy port

Both `vaultwarden` and `caddy` publish on a random host port (`"0:80"` /
`"0:8443"`) to avoid collisions between parallel test runs:

```bash
docker compose -f docker-compose.vaultwarden.yml port caddy 8443
# e.g. 0.0.0.0:54321
```

Use that port for every `https://localhost:<port>` reference below.

## 3. Trust Caddy's internal CA (so `bw` itself accepts the cert)

Caddy's internal CA root is generated on first run and persisted in the
`caddy_data` volume at `/data/caddy/pki/authorities/local/root.crt`. Extract
it to the host:

```bash
docker compose -f docker-compose.vaultwarden.yml exec caddy \
  cat /data/caddy/pki/authorities/local/root.crt > /tmp/vaultwarden-e2e-ca.crt
```

You need the `bw` CLI itself (not just your browser or `curl`) to trust
this cert, or every `bw` invocation against the fixture will fail with a
TLS verification error. Two ways to do that, in order of preference:

### Preferred: `NODE_EXTRA_CA_CERTS` (no system trust-store changes)

The official `@bitwarden/cli` package is a Node.js binary — Node respects
`NODE_EXTRA_CA_CERTS` for exactly this case (an extra CA to trust for this
process only, without touching the OS trust store):

```bash
export NODE_EXTRA_CA_CERTS=/tmp/vaultwarden-e2e-ca.crt
```

Set this in the same shell/session you run `bw config server` and
`make test-e2e-bw` from. This is scoped to the current shell — nothing is
installed system-wide, and unsetting the variable (or closing the shell)
fully reverts it.

### Alternative: trust the CA in the OS keychain

Only do this if your `bw` build doesn't respect `NODE_EXTRA_CA_CERTS` (e.g.
a non-Node/native build). This DOES modify your system trust store — remove
the cert again once you're done testing.

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/vaultwarden-e2e-ca.crt

# Linux (Debian/Ubuntu)
sudo cp /tmp/vaultwarden-e2e-ca.crt /usr/local/share/ca-certificates/vaultwarden-e2e.crt
sudo update-ca-certificates
```

Remove it afterward:

```bash
# macOS
sudo security delete-certificate -c "Caddy Local Authority" /Library/Keychains/System.keychain

# Linux
sudo rm /usr/local/share/ca-certificates/vaultwarden-e2e.crt
sudo update-ca-certificates --fresh
```

## 4. Point `bw` at the fixture and create a test account

```bash
bw config server https://localhost:<port>

# Vaultwarden allows self-registration by default in this fixture
# (no SMTP configured — there's no email verification step to complete).
bw register you@example.com 'a-throwaway-password' --name "Keylatch E2E"

bw login you@example.com 'a-throwaway-password' --raw
# ^ this IS the login step; --raw prints only the session token if you're
#   already logged in from a prior run — otherwise log in normally first,
#   then run `bw unlock --raw` to get a session token:
export BW_SESSION="$(bw unlock --raw)"
```

Never commit these throwaway credentials anywhere; they only exist inside
the ephemeral Vaultwarden container.

## 5. Run the E2E test

```bash
export KEYLATCH_E2E_BW_SERVER="https://localhost:<port>"
# BW_SESSION already exported from step 4.
make test-e2e-bw
```

`cmd/keylatch/bw_init_e2e_test.go` pushes a throwaway item, lists it back,
and cleans it up — no docker/bw invocation happens from within the Go test
itself; it talks to the already-running fixture via the `bw` CLI configured
above.

## 6. Tear down

```bash
docker compose -f docker-compose.vaultwarden.yml down -v
```

`-v` removes the `caddy_data` volume too, so the next run generates a fresh
internal CA (and you'll need to re-trust it — repeat step 3).

## Notes

- This fixture, the Caddy sidecar, and `tls internal` are TEST-ONLY. No
  production code path uses a self-signed cert or skips TLS verification —
  `bw.Open()`'s `https://` check and Go's default TLS verification are
  never bypassed anywhere in `internal/backend/bw`.
- If you only need to poke at Vaultwarden over plain HTTP (e.g. the admin
  UI) without exercising the TLS-bridged path, `vaultwarden`'s own
  `"0:80"` published port still works directly — `bw.Open()` will still
  reject that URL for the actual E2E test, this is for manual debugging
  only.
