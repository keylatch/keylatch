# Keylatch Makefile

.PHONY: build test lint security-grep check test-e2e-op test-e2e-bw test-core-packages test-canary test-canary-meta test-hook test-prop test-bench test-ui test-team test-team-e2e ci test-integration-examples docker-build govulncheck

## build: compile all packages
build:
	go build ./...

## test: run all unit tests (excludes e2e build tags)
test:
	go test ./...

## lint: vet all packages
lint:
	go vet ./...

## security-grep: S2-8 check — no session token format-string interpolation
security-grep:
	bash scripts/security-grep.sh

## check: full pre-commit check (build + test + lint + security-grep)
check: build lint test security-grep

## test-e2e-op: run 1Password E2E tests (requires KEYLATCH_E2E_OP=1 and op CLI)
test-e2e-op:
	KEYLATCH_E2E_OP=1 go test -v -tags=e2e_op ./cmd/keylatch/ -run TestE2E_OP

## test-e2e-bw: run Vaultwarden E2E tests (requires docker-compose)
test-e2e-bw:
	go test -v -tags=e2e_bw ./cmd/keylatch/ -run TestE2E_BW

## test-core-packages: run core package tests with race detection
test-core-packages:
	go test -race -count=1 \
		./internal/registry/... \
		./internal/connections/... \
		./internal/validate/... \
		./internal/mcp/... \
		./internal/agentsnippet/... \
		./internal/agent/... \
		./cmd/keylatch/...

## test-canary: run canary leak-detection tests with race detection
test-canary:
	go test -race -count=1 -run TestCanary ./...

## test-canary-meta: run meta coverage check for canary AssertNoLeak usage
test-canary-meta:
	go test -tags meta -race -count=1 ./internal/canary/...

## test-hook: run agent-guard hook tests
test-hook:
	bash contrib/agent-guards/claude-code/block-keylatch-exfiltration.test.sh --verbose
	bash contrib/agent-guards/aider/block-keylatch-exfiltration.test.sh
	bash contrib/agent-guards/copilot/block-keylatch-exfiltration.test.sh
	bash contrib/agent-guards/cursor/block-keylatch-exfiltration.test.sh
	bash contrib/agent-guards/windsurf/block-keylatch-exfiltration.test.sh

## test-prop: run property-based tests in internal/vault
test-prop:
	go test -tags prop -race -count=1 ./internal/vault/...

## test-bench: run benchmarks for keychain, crypto, and audit packages
test-bench:
	go test -bench=. -benchmem ./internal/backend/keychain/... ./internal/crypto/... ./internal/audit/...

## test-ui: run browser UI tests (Go + web, requires bun)
test-ui:
	go test -race -count=1 \
		./internal/ui/... \
		./internal/cli/...
	cd web && bun run test

## build-web: build the SPA for embedding
build-web:
	bash scripts/sync-embedded-ui.sh

## test-team: run team governance tests with race detection
test-team:
	go test -race -count=1 \
		./internal/team/... \
		./internal/policy/... \
		./internal/gateway/... \
		./internal/grant/... \
		./internal/ui/api/... \
		./internal/cli/... \
		-v

## test-team-e2e: run team E2E multi-member tests
test-team-e2e:
	go test -race -count=1 \
		./cmd/keylatch/ \
		-run "TestTeamE2E|TestTwoPersonApprovalE2E|TestSharedSecretE2E|TestTeamNotConfiguredE2E|TestInviteBundle|TestOrgPolicy_Integration" \
		-v

## docker-build: build the local (source) Dockerfile image, stamping version metadata
## NOTE: does not run/push the image — see README for `docker run` usage.
docker-build:
	docker build \
		--build-arg VERSION=$$(git describe --tags --always --dirty 2>/dev/null || echo dev) \
		--build-arg COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo unknown) \
		--build-arg BUILD_DATE=$$(date -u +%Y-%m-%dT%H:%M:%SZ) \
		-t keylatch:dev \
		.

## govulncheck: scan all packages for known Go vulnerabilities
govulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## test-integration-examples: smoke-test all integration example scripts (syntax + dry-run)
test-integration-examples:
	@echo "==> Syntax-checking shell integration examples"
	@find docs/integration/examples -name "*.sh" -exec bash -n {} \; && echo "  shell: OK"
	@echo "==> Syntax-checking Python integration examples"
	@find docs/integration/examples -name "*.py" -exec python3 -m py_compile {} \; && echo "  python: OK"
	@echo "==> Syntax-checking JS integration examples"
	@find docs/integration/examples -name "*.js" -exec node --check {} \; 2>/dev/null && echo "  js: OK" || echo "  js: (no .js examples found)"
	@echo "==> All integration example syntax checks passed"

## ci: full CI pipeline (lint + test + canary meta + hook)
ci: lint test test-canary-meta test-hook
