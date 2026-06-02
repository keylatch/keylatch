# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-01

> **Note on code-signing (1.0.0):** Desktop binaries are not code-signed in this release. On macOS, run `xattr -dr com.apple.quarantine keylatch.app` if Gatekeeper blocks the app. On Windows, dismiss the SmartScreen prompt. Code-signing will be added in a future release.

### Zero-trust credential vault

Keylatch 1.0.0 is the first stable release. It is designed for security-conscious developers who run AI coding agents and need to keep API keys out of model context, MCP tool outputs, and agent logs.

### What you get

- **LLM session blocking** — Claude Code, Codex, Cursor, Aider, Gemini CLI, and OpenCode are auto-detected. Direct credential reads (`keylatch get`) are blocked with exit code 2 inside any detected session.
- **4 credential backends** — macOS Keychain (hardware-backed), 1Password CLI, Bitwarden CLI, and an encrypted file (XChaCha20-Poly1305 / AES-256-GCM). Backend can be switched at runtime with live key migration.
- **Desktop app** — macOS, Windows, and Linux. Includes a first-run wizard, tray icon, approval inbox, and agent profile setup — no terminal required for day-to-day use.
- **Full web UI** — connections list, per-connection approval policy override, diagnostics, settings, and a live receipt stream.
- **Per-connection approval policy override** — set Trust, Prompt, or First-run per provider without touching the global default.
- **Credential backend switcher** — switch between Keychain, 1Password, Bitwarden, and encrypted file in Settings (Advanced mode). Vault key is migrated automatically; app restarts on completion.
- **Gateway middlewares enforced** — `authBlockerMiddleware`, `hostOverrideBlockerMiddleware`, and `SSRFGate` are now active at runtime. Agent-supplied `api_key` query params, `X-Forwarded-Host` headers, and SSRF-class upstream hosts are blocked.
- **MCP server** — 5 tools for AI agent integration via the MCP protocol.

### Security fixes (wired for the first time in 1.0.0)

- Gateway middlewares (`authBlockerMiddleware`, `hostOverrideBlockerMiddleware`, `SSRFGate`) were implemented in earlier alpha phases but never invoked at runtime. They are now wired. Upgrading from 0.1.0-alpha is strongly recommended.
- Token cache is now bounded (1000 entries, FIFO eviction) — eliminates unbounded-map memory growth under sustained load.
- Strict Content-Security-Policy with no `'unsafe-inline'` in `script-src` and no wildcard in `connect-src`.

### Release pipeline

- SBOM published in CycloneDX and SPDX formats for every release.
- Release artifacts signed with cosign via GitHub Actions OIDC (keyless).
- Dependabot enabled for Go modules, npm, Cargo, and GitHub Actions (weekly, conventional-commit prefix).

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
