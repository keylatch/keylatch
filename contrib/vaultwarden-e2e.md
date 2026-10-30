# Vaultwarden collections and restore tests

The tests provision a new account and organization in a disposable Vaultwarden 1.37.4 service. They install the pinned official Bitwarden CLI from `tests/e2e/bitwarden/package-lock.json`. No existing account, session token, organization, or system certificate installation is needed.

Each client uses a separate temporary `BITWARDENCLI_APPDATA_DIR`. A test HTTPS reverse proxy forwards only to the explicitly configured HTTP loopback service. Its certificate is trusted only by the test clients through `NODE_EXTRA_CA_CERTS`; production TLS checks remain enabled. Generated passwords go through a child environment variable, never command arguments or test output.

## Run locally

Start a disposable Vaultwarden service on a loopback port, with registration enabled and no persistent volume. In this monorepo, use `infractl dev services` with this project declaration in `.claude/test-services.json`:

```json
{
  "engine": "podman",
  "ttlMinutes": 60,
  "services": {
    "vaultwarden": {
      "image": "docker.io/vaultwarden/server:1.37.4",
      "port": 8080,
      "hostPort": 18280,
      "env": {"ROCKET_PORT": "8080", "SIGNUPS_ALLOWED": "true"},
      "tmpfs": ["/data"],
      "readySeconds": 30
    }
  }
}
```

Run these commands with the absolute checkout path substituted for `/path/to/keylatch`:

```sh
infractl dev services up /path/to/keylatch vaultwarden
npm --prefix /path/to/keylatch/tests/e2e/bitwarden ci --ignore-scripts --no-audit --no-fund
env KEYLATCH_E2E_VAULTWARDEN_URL=http://127.0.0.1:18280 \
  KEYLATCH_E2E_BW_BIN=/path/to/keylatch/tests/e2e/bitwarden/node_modules/.bin/bw \
  make -C /path/to/keylatch test-e2e-bw
infractl dev services down /path/to/keylatch
```

The service stores only generated test accounts and data; stopping it discards them. Use an unused host port if 18280 is occupied. The fixture refuses remote addresses, embedded credentials, query parameters, and non-HTTP upstream origins.

## What runs

- The collections test writes through a namespace mapping and checks the real CLI's organization and collection metadata.
- Clean restore imports three items, serializes and reloads the manifest, re-derives its key, then verifies through a fresh client login and empty CLI data directory.
- Missing-item restore deletes one backend item before the fresh client login.
- Changed-item restore replaces one value before the fresh client login and checks the manifest mismatch.

The tests use separate accounts, so fixed item names cannot collide across runs. The importer and restore verifier do not share a backend object or CLI cache.

## CI

`.github/workflows/vaultwarden.yml` starts its own service and installs the locked CLI dependency. Both normal CI and the scheduled security integration job call it. `KEYLATCH_E2E_BW_REQUIRED=1` makes missing fixture configuration fail instead of skip. Individual developer invocations without that flag may skip when no disposable service is configured.

The older Caddy Compose stack remains available for manual investigation; these tests do not require it or a preconfigured Bitwarden client.
