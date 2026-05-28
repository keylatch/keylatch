# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SBOM generation (syft, CycloneDX + SPDX) added to the release workflow.
- Dependabot configuration covering gomod, npm, cargo, and github-actions ecosystems on a weekly cadence with conventional-commit prefixed PRs.
- CI `go-mod-tidy` job — catches dependency-graph drift on every push and PR instead of only at release time.
- CI `desktop-lint` job — wires the three Phase 14 lint scripts (S14-6 notification fields, S14-8 IPC method allow-list, S14-14 no-secret-in-storage) into the test workflow.
- `.golangci.yml` with errcheck/govet/ineffassign/staticcheck/unused/gosec in new-issues-only mode (`--new-from-rev=origin/main`).
- `Formula/keylatch.rb` — stub Homebrew formula for manual taps (release tarballs are still produced by the goreleaser `brews` stanza).
- `.github/scoop/keylatch.json` — stub Scoop manifest.
- `Dockerfile` upgraded to a multi-stage build (`golang:1.25-alpine` builder, `gcr.io/distroless/static` runtime).
- UI server: `GET /health` (value-free liveness probe) and `GET /metrics` (Prometheus placeholder).
- Structured logging via `log/slog` in `internal/trust/pkcs11` (replaces the last remaining `log.Printf` call).
- Tests for `internal/gateway/approval` — coverage raised from 0% to 90.9%.

### Changed
- `internal/broker/cache.go` — token cache is now bounded (default 1000 entries, FIFO eviction on overflow). Closes the unbounded-map memory growth path.
- `tests/e2e/receipt_card.spec.ts` — CSP assertion now matches the strict policy emitted by `internal/ui/middleware.go` (no `'unsafe-inline'` in script-src, no `http://127.0.0.1:*` wildcard in connect-src).
- `go.mod` cleaned: `fxamacker/cbor/v2`, `golang-jwt/jwt/v5`, `golang.org/x/crypto`, `golang.org/x/sys`, and `gopkg.in/yaml.v3` promoted from indirect to direct dependencies after `go mod tidy`.

### Security
- Gateway HTTP server now wires `authBlockerMiddleware`, `hostOverrideBlockerMiddleware`, and `SSRFGate` into the proxy route. Previously the three middlewares were implemented but never invoked at runtime — agent-supplied `api_key` query params, `X-Forwarded-Host` headers, and SSRF-class upstream hosts could bypass the gateway's credential isolation. See `internal/gateway/server.go` and `internal/gateway/handler.go`.
- `authBlockerMiddleware` no longer blocks the `Authorization` header (the gateway consumes it as the keylatch session JWT and strips it before forwarding upstream). Upstream-credential isolation is enforced by the handler's strip-and-inject logic; `Authorization` blocking would have prevented all gateway authentication.
- `hostOverrideBlockerMiddleware` is configured with an empty allowed-hosts list, enforcing only the strong subset of its rules: blocking `X-Forwarded-Host`, `X-Original-URL`, and `X-Rewrite-URL` headers. The inbound `Host` header always points at the loopback gateway address, not the upstream destination.

## [0.1.0-alpha] - 2026-05-13

### Added — Phase 0 — Go CLI skeleton with LLM session guard
- Zero-trust LLM session guard: `CLAUDE_CODE`, `CODEX_ENV`, `CREDENTIALS_LLM_SESSION`, `CURSOR_SESSION`, `AIDER_SESSION`, `GEMINI_SESSION`, `OPENCODE_SESSION` env detection.
- Portable bootstrap and doctor commands for setup and diagnostics.

### Added — Phase 1 — Credential backends
- File backend with AEAD-encrypted at-rest storage.
- macOS Keychain backend (custom keychain at `~/.keylatch/keylatch.keychain-db` with item-level entries).

### Added — Phase 2 — Password-manager backends
- 1Password CLI (`op`) backend with passphrase-derived KEK.
- Bitwarden CLI (`bw`) backend with passphrase-derived KEK.

### Added — Phase 3 — Registry, MCP, agent snippets
- Provider connection registry with template YAML format.
- MCP server exposing 5 tools for AI agent integration via `modelcontextprotocol/go-sdk` v1.6.0.
- Agent snippet generation for Claude, Cursor, Codex, and Aider.

### Added — Phase 4 — Metadata, versions, expiry
- Versioned secret storage with rollback support.
- Per-secret metadata (TTL, expiry, tags, notes).
- `keylatch set`, `versions`, `destroy-version`, `rollback`, and `check-expiry` CLI commands.

### Added — Phase 5 — Envelope crypto + audit
- AEAD envelope primitives (XChaCha20-Poly1305 default, AES-GCM under FIPS).
- KEK providers: passphrase (Argon2id), keychain, op, bw, age.
- HMAC-chained audit log with rotation and tamper-resistance.
- Keyring init / rotate-term / rotate-kek / destroy-term / status CLI commands.

### Added — Phase 6 — Test suite
- Canary leak detection package (`internal/canary`).
- Audit chain HMAC verification (`internal/auditverify`).
- MockRunner for deterministic CLI tests.
- Cross-platform CI workflows (ubuntu, macos, windows).

### Added — Phase 7 — Packaging, docs, release
- `goreleaser` config producing tar.gz (Linux/macOS) and zip (Windows) archives, with `brews`, `scoops`, and `dockers` stanzas.
- `release-gates/` shell scripts (sbom-verify, docs-scan, provider-template-validate, secret-format-check, reproducible-build).
- Contributor docs: README, CONTRIBUTING, SECURITY, examples, and `docs/` site.

### Added — Phase 8 — Policy, actors, grants
- Policy engine with actor + capability matching and TTL-bound grants.
- Persistent grant lifecycle with file-backed storage.
- `keylatch policy`, `actor`, `grant` CLI commands.

### Added — Phase 9 — Local typed gateway
- Local gateway HTTP server (default `127.0.0.1:7878`) with a 12-step request lifecycle: JWT verify → route match → capability check → LLM-session gate → policy check → substitution prevention → vault.Get → broker.Exchange → upstream call → redact → audit → respond.
- Sub-packages: `token` (JWT), `redact`, `substitution`, `broker`, `approval`, `route`.
- Docker mode for sandboxed gateway runs.

### Added — Phase 10 — Localhost UI
- `keylatch ui` command launches a local browser dashboard at `127.0.0.1:7890`.
- Bootstrap-token + HttpOnly session cookie + CSRF double-submit pattern.
- Strict Content-Security-Policy with no `'unsafe-inline'` or wildcards.
- Embedded SPA (Vite + React) served from the Go binary.
- Connections, approvals, gateway, broker, audit, and agent API endpoints.

### Added — Phase 11 — Roots of trust
- Pluggable trust adapter layer with 7 backends: keychain (macOS Secure Enclave hooks), file, FIDO2, GPG card, PKCS#11, SSH agent, HashiCorp Vault, and fallback.
- Attestation infrastructure for trust roots.

### Added — Phase 12 — Team governance
- Organization policy layer with SCIM-style user/group sync.
- Org-level decision composition (deny-filter; capability-ceiling work tracked separately).
- Shared-secret rotation infrastructure.
- CI claims for headless team workloads.

### Added — Phase 13 — Token broker, masking, proxy
- Token broker with cache, lease, and revocation lifecycle.
- Masking/redaction layer for credential values in responses.
- Advanced proxy controls (per-route TTL, allowed params, max body size).

### Added — Phase 14 — Desktop product shell
- Tauri-based desktop app (`keylatch-app`) with a Rust shell + embedded keylatch sidecar.
- IPC channel using key-via-FD handoff (no key bytes in CLI args or env).
- Approval flow with system-tray notifications.
- OAuth callback handler for browser-based flows.
- Single-instance lock to prevent racing sidecar processes.
- Auto-update infrastructure (currently disabled — `active: false` in `tauri.conf.json` pending signing-key provisioning).

### Security
- Canary sentinel infrastructure (`internal/canary`) for leak detection in tests.
- Audit chain HMAC verification (`internal/auditverify`).
- LLM session blocking on all value-bearing CLI commands.
- Agent-guard hook: `contrib/agent-guards/claude-code/block-keylatch-exfiltration.sh`.
