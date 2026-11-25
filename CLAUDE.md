# CLAUDE.md — keylatch

See [AGENTS.md](./AGENTS.md) for agent reference.

## What

keylatch: a go project.

## Structure

```
Formula/
assets/
cmd/
contrib/
docs/
examples/
installers/
internal/
packaging/
release-checks/
scripts/
services/
src-tauri/
templates/
tests/
web/
```

## How

```bash
make build                # build: compile all packages
make test                 # test: run all unit tests (excludes e2e build tags)
make lint                 # lint: vet all packages
make security-grep        # security-grep: no session token format-string interpolation
make check                # check: full pre-commit check (build + test + lint + security-grep)
make test-e2e-op          # test-e2e-op: run 1Password E2E tests (requires KEYLATCH_E2E_OP=1 and op CLI)
make test-e2e-bw          # test-e2e-bw: run Vaultwarden E2E tests (requires docker-compose)
make test-core-packages   # test-core-packages: run core package tests with race detection
make test-canary          # test-canary: run canary leak-detection tests with race detection
make test-canary-meta     # test-canary-meta: run meta coverage check for canary AssertNoLeak usage
make test-hook            # test-hook: run agent-guard hook tests
make test-security-suite  # test-security-suite: run the security regression tests (memory-heavy
go build ./...            # Build
go test ./...             # Run tests
go vet ./...              # Vet
```

## Status: active
