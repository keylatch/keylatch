# Contributing to Keylatch

Thank you for your interest in contributing to Keylatch.

## Prerequisites

- **Go 1.22+** — [golang.org/doc/install](https://golang.org/doc/install)
- **Bun** — for docs and UI tooling ([bun.sh](https://bun.sh))
- **cosign** — for provider bundle signing ([docs.sigstore.dev](https://docs.sigstore.dev/cosign/overview/))
- **yq** — for YAML validation in release gates

## Local Setup

```bash
git clone https://github.com/keylatch/keylatch.git
cd keylatch
go mod download
```

## Running Tests

```bash
# All unit tests
go test ./...

# With race detection
go test -race ./...

# Vet all packages
go vet ./...

# Full pre-commit suite (build + lint + test + security scan)
make ci

# Canary leak tests
make test-canary
```

## Running Coverage Locally

```bash
# Generate coverage profile
go test -coverprofile=coverage.out ./...

# Check the 85% threshold gate (same script CI runs)
bash release-gates/coverage-threshold.sh coverage.out

# Print per-package report even when the gate passes
bash release-gates/coverage-threshold.sh coverage.out --report

# Open an interactive HTML coverage view in the browser
go tool cover -html=coverage.out
```

The gate reads `release-gates/coverage-allowlist.txt` to skip packages that are
intentionally below threshold (hardware drivers, CLI entry points, test helpers).
If you add a new package, make sure it either reaches 85% or is added to the
allowlist with a one-line rationale.

## Adding a Provider Template

Provider templates live in `templates/providers/`. Each template is a YAML file
validated against `templates/providers/schema.json` (JSON Schema draft-07).

1. Copy an existing template as a starting point.
2. Fill in all required fields: `provider`, `display_name`, `category`,
   `secret_fields`, `auth_flow`, `storage_path_tpl`, `trust_level`.
3. Validate your template:
   ```bash
   keylatch registry validate templates/providers/my-provider.yaml
   ```
4. Run the full provider template validation gate:
   ```bash
   bash release-gates/provider-template-validate.sh
   ```
5. Open a pull request. The CI pipeline runs validation automatically.

See [`templates/providers/README.md`](templates/providers/README.md) for field
descriptions and the full schema reference.

## Pre-commit Hooks

Keylatch uses [Husky](https://typicode.github.io/husky/) for pre-commit and
commit-msg hooks.

Install hooks after cloning:

```bash
bun install
```

The `pre-commit` hook runs:
- `go vet ./...`
- `gofmt` check (fails if any file is not formatted)
- Basic secret scan on staged files (rejects `sk-*` or `ghp_*` tokens not in canary/test files)

The `commit-msg` hook enforces [Conventional Commits](https://conventionalcommits.org/)
via `commitlint`.

## Building the Desktop App

The Tauri desktop app requires `keylatchd` to be built and staged before the Tauri bundle step:

1. Build the sidecar: `go build -o src-tauri/binaries/keylatchd-aarch64-apple-darwin ./cmd/keylatchd` (adjust triple for your platform)
2. Build web assets: `cd web && bun run build`
3. Build the app: `cd src-tauri && cargo tauri build`

Or use goreleaser to build and stage automatically: `goreleaser release --snapshot --clean`

## Org-Scoped Registry

An organisation-scoped provider registry (Phase 12) will allow teams to host
private provider templates. Contributing private templates back to the public
registry is encouraged via a separate template review process — details TBD.

## Code Style

- `gofmt` — all Go files must be formatted with `gofmt`.
- `go vet` — no vet warnings.
- No `any` types — use concrete types or `interface{}` with a comment.
- Canary values only in test and example files — never real credentials.

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Write or update tests for any behaviour change.
3. Run `make ci` and confirm it passes.
4. Open a pull request against `main` with a clear description.
5. At least one maintainer review is required before merge.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache-2.0 License](LICENSE).
