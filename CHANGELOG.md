# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Canonical backend-name catalog** (`internal/backend/catalog.go`). Backend identifiers are now normalized to a single canonical form at every entry point (dispatch settings resolution, bootstrap config validation, `config` CLI): `awssm`/`aws-secrets` → `aws-sm`, `protonpass` → `proton-pass`, `hashivault` → `vault`, `opconnect` → `op-connect`, `gcpsm` → `gcp-sm`, `azurekv`/`azure-keyvault` → `azure-kv`. Old aliases are still accepted as input for backwards compatibility, but `config.json` should persist the canonical name going forward.
- Per-backend environment-variable wiring for the external/cloud backends (`vault`, `aws-sm`, `gcp-sm`, `azure-kv`, `doppler`, `infisical`, `op-connect`), including fallback to each provider's own conventional env vars (e.g. `VAULT_ADDR`, `AWS_REGION`, `AZURE_TENANT_ID`) when the `KEYLATCH_*`-prefixed var and config field are both unset. See [Environment Variables](docs/cli/environment.md#backend-variables).
- `embedded_ui` build tag: release builds (`goreleaser`, GitHub Actions) now embed the real web UI bundle via `go:embed` when compiled with `-tags embedded_ui`; source/dev builds without the tag continue to serve a diagnostic fallback page.

### Changed

- **Setup wizard is now resumable.** `keylatch setup` no longer aborts when `~/.keylatch/config.json` already exists with an incomplete backend — it repairs/continues onboarding instead of requiring a manual reset.
- Removed OS-daemon auto-spawn (launchd/systemd) plumbing from the setup wizard in favor of starting the local gateway directly in step 3 ("Gateway setup"). No user-facing change to the wizard's step count or flow, only to how the gateway process is brought up.

### Removed

- **NordPass backend stub removed** (`internal/backend/nordpass`). The stub was never imported by `internal/backend/all` or listed in the backend catalog, so it could never actually be selected — even with `KEYLATCH_EXPERIMENTAL=1` set. Removed rather than half-wired; see [Experimental Features](docs/experimental.md) for the removal note. No functional change for any user, since the backend was already unreachable.

### Fixed

- Documentation: the README "Desktop app" section and `docs/` no longer describe the desktop app as macOS/Windows/Linux. Corrected to match the MVP — the desktop app ships for Linux; macOS/Windows are deferred (use the CLI's `keylatch ui`).
- Documentation: corrected config-vs-env precedence claims across `docs/configuration.md`, `docs/cli/environment.md`, and `docs/troubleshooting.md` — precedence differs per subsystem (backend selection is config-over-env; operating mode is env-over-config) rather than a single global rule. Removed two dead documented variables with no code reader (`KEYLATCH_AUDIT__ENABLED`, `KEYLATCH_GATEWAY__ENDPOINT`) and fixed a typo'd variable name (`KEYLATCH_AUDIT__PATH` → `KEYLATCH_AUDIT_PATH`).
- Documentation: `docs/cli/environment.md` now documents previously-undocumented active variables (`KEYLATCH_DAEMON_SOCKET`, proxy child-injected `KEYLATCH_SESSION_TOKEN`/`KEYLATCH_CA_CERT`, `KEYLATCH_PKCS11_PIN`, Windows `KEYLATCH_IPC_KEY`) and the non-`KEYLATCH_*` provider aliases accepted by cloud backends. Marked `KEYLATCH_DAEMON_STATE_PATH` deprecated (no remaining code reader). Corrected the proxy-mode child-env summary, which previously claimed no `KEYLATCH_*` vars are forwarded and listed `SHELL` in the base env (`internal/runner/driver_proxy.go` does not include `SHELL`).
- Documentation: Docker instructions (`README.md`, `docs/installation.md`) previously showed mounting `~/.keylatch` to `/root/.keylatch`, which does not work — the image runs as the distroless `nonroot` user (UID 65532), not root. Corrected to use `KEYLATCH_CONFIG_DIR=/home/nonroot/.keylatch` with a matching volume mount, documented the new `KEYLATCH_UI_LISTEN` opt-in for reaching the browser UI from outside the container, replaced a broken example that published a port without passing a subcommand (the entrypoint just prints `--help` and exits), and corrected `docs/installation.md` calling the image a "`keylatchd` sidecar image" — it ships only the `keylatch` CLI. Documented which backends actually work inside the distroless container (file, `aws-sm`, `vault`) versus which require a CLI binary the image doesn't ship (`op`, `bw`, `keychain`, `lastpass`, `keeper`, `proton-pass`).
- Documentation: `docs/getting-started.md` setup-wizard step labels were stale (`[3/5] Daemon setup...`, `[5/5] Open Keylatch app (optional)...`) — updated to match current CLI output (`[3/5] Gateway setup...`, `[5/5] Open Keylatch UI (optional)...`).

### Security

- Gateway proxy mode (`gateway_proxy`) now enforces per-session bearer authentication by default on the local MITM proxy, closing a gap where an unauthenticated caller on the loopback proxy port could act as the child process. Scoped to `gateway_proxy` runs.
- Raw-credential commands now require a verified session. `keylatch get` and `keylatch run` in a raw-credential-exposure mode (`direct_brokered`, `direct_classic_sandboxed` — the modes that place a real secret in the child's environment) now require positive corroboration that the caller is trusted: a signed session ticket (`KEYLATCH_LLM_TICKET`) or a reachable `keylatchd`. Without either, the command **fails closed** with exit code 2 — for *every* session, including one that has unset all LLM-detection signals to look human (this closes the prior spoof-to-human bypass). Gateway modes (`gateway_typed`, `gateway_sdk`, `gateway_proxy`) are **never** gated by this check, for any session, because the child there only ever receives a scoped session token, never a raw secret.
  - **Potentially breaking**: a user who runs `keylatch get` or a direct-mode `keylatch run` *without* `keylatchd` running will now be refused unless they opt out. Opt out permanently by setting `allow_unverified_session: true` in `config.json`, or per-invocation with `KEYLATCH_ALLOW_UNVERIFIED_SESSION=1`. Running `keylatchd`, or using a gateway/proxy run, requires no change.
- `keylatch run --extra` now withholds credential-shaped variables from the child. In addition to the existing exact-name provider-key denylist, any `--extra` name whose (case-insensitive) form ends in or contains `_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD`, `_PASSWD`, `_CREDENTIAL(S)`, or `_PRIVATE_KEY` is no longer copied into the `gateway_proxy` child; a warning naming each withheld variable is printed to stderr. Prevents a caller from leaking a real provider secret into the agent by requesting it via `--extra`.
- `--listen` / `KEYLATCH_UI_LISTEN` / `KEYLATCH_GATEWAY_LISTEN` values are now validated as `host:port` before binding, returning a clear error instead of a raw `net.Listen` failure. (Non-loopback binds remain refused inside a detected LLM session regardless.)
- Container images are now scanned and signed in CI as part of the release pipeline: per-arch Trivy vulnerability scanning plus cosign signing and a CycloneDX SBOM attestation on the multi-arch **manifest-list digest** (what `docker pull` resolves), in addition to the existing CLI-archive/SBOM blob signing.

## [0.9.4] - 2026-06-24

First MVP-scoped release: ships the self-contained CLI (macOS/Windows/Linux), the Docker image, and the Linux desktop app (AppImage/.deb). macOS and Windows desktop apps are deferred to a post-MVP release — use the CLI on those platforms (`keylatch ui` provides the browser GUI).

### Changed

- **MVP distribution scope.** Release builds ship the **Linux desktop bundle (AppImage/.deb) only**; the macOS `.dmg` and Windows `.exe` desktop apps are deferred to a post-MVP release to avoid code-signing certificate costs. The Tauri code stays in the repo — re-enable macOS/Windows desktop builds by setting the `DESKTOP_OS_MATRIX` repo variable (no code change). On macOS/Windows, use the self-contained CLI; `keylatch ui` provides the same browser GUI.

### Added

- Linux desktop bundle is now **cosign-signed** alongside the CLI archives, checksums, and SBOM.
- `docs/architecture/signing.md` — explains the three signing systems and how keyless cosign works.

## [0.9.3] - 2026-06-23

Maintenance release on the 0.9.x public-alpha line. No behavioural changes to the vault, gateway, or guard — this release fixes how the installers are versioned and how the release is published so external testers get a correct, unambiguous build.

> **Note on code-signing (0.9.3):** Unchanged from 0.9.2 — desktop binaries are not code-signed. On macOS, run `xattr -dr com.apple.quarantine keylatch.app` if Gatekeeper blocks the app. On Windows, dismiss the SmartScreen prompt.

### Fixed

- **Desktop installers now carry the release version.** Previously the `.dmg`, `.exe`, `.AppImage`, and `.deb` were stamped with the static manifest version rather than the release tag (e.g. an `0.9.3` release shipping `0.9.2`-labelled installers). The release pipeline now stamps the desktop bundle version from the git tag, matching the CLI artifacts.
- **Pre-release tags are no longer published as "Latest".** Hyphenated tags (`-alpha`/`-beta`/`-rc`) are now flagged as GitHub pre-releases, so a clean `0.9.x` tag is the default download for testers and internal alphas no longer shadow it.

### Changed

- Substantial test-coverage hardening across credential backends (1Password, Bitwarden, Infisical, NordPass, GCP SM, Azure KV), IPC, exec, and agent presets — `internal/exec` now enforced at the 85% coverage gate.
- CI hygiene: longer `go-test` timeout, untracked the stray `release-manifest` binary, and cosign identity verification now accepts pre-release tags.

## [0.9.2] - 2026-06-11

*Originally drafted as 1.0.0; re-versioned — 1.0.0 ships after the alpha cycle.*

> **Note on code-signing (0.9.2):** Desktop binaries are not code-signed in this release. On macOS, run `xattr -dr com.apple.quarantine keylatch.app` if Gatekeeper blocks the app. On Windows, dismiss the SmartScreen prompt. Code-signing will be added in a future release.

### Zero-trust credential vault

Keylatch 0.9.2 is the stabilization release before the v1.0.0-alpha cycle. It is designed for security-conscious developers who run AI coding agents and need to keep API keys out of model context, MCP tool outputs, and agent logs.

### What you get

- **LLM session blocking** — Claude Code, Codex, Cursor, Aider, Gemini CLI, and OpenCode are auto-detected. Direct credential reads (`keylatch get`) are blocked with exit code 2 inside any detected session.
- **4 credential backends** — macOS Keychain (hardware-backed), 1Password CLI, Bitwarden CLI, and an encrypted file (XChaCha20-Poly1305 / AES-256-GCM). Backend can be switched at runtime with live key migration.
- **Desktop app** — macOS, Windows, and Linux. Includes a first-run wizard, tray icon, approval inbox, and agent profile setup — no terminal required for day-to-day use.
- **Full web UI** — connections list, per-connection approval policy override, diagnostics, settings, and a live receipt stream.
- **Per-connection approval policy override** — set Trust, Prompt, or First-run per provider without touching the global default.
- **Credential backend switcher** — switch between Keychain, 1Password, Bitwarden, and encrypted file in Settings (Advanced mode). Vault key is migrated automatically; app restarts on completion.
- **Gateway middlewares enforced** — `authBlockerMiddleware`, `hostOverrideBlockerMiddleware`, and `SSRFGate` are now active at runtime. Agent-supplied `api_key` query params, `X-Forwarded-Host` headers, and SSRF-class upstream hosts are blocked.
- **MCP server** — 5 tools for AI agent integration via the MCP protocol.

### Security fixes (wired for the first time in 0.9.2)

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
