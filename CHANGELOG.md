# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Historical note**: the tag `v1.0.0-rc.1` predates a 2026-05-28 history
> rewrite and has no merge-base with current `main`. It is kept (not deleted)
> as a pointer into the pre-rewrite history, but does not correspond to any
> entry in this changelog and is not part of the `v0.9.x` release train
> below — do not treat it as "ahead of" or otherwise related to the current
> version numbering.

## [Unreleased]

### Added

- `keylatch mint <connection> --repo <owner/name> --permission <name>=<level> … --format json` mints a GitHub App installation token for exactly one repository and the listed permissions, and prints `{"token","expires_at","repository","permissions"}`. The App JWT is signed inside Keylatch; the private key never leaves it. Exit codes: 1 usage, 2 agent session or no audit log, 3 policy, 4 store unavailable, 5 GitHub refused or the token was revoked, 6 connection field missing.
- `github-app` provider template: `private_key` (secret), `app_id` and one `installation_<owner>` field per account the App is installed on. `keylatch connect github-app` tests the connection with a signed App JWT against `GET /app`.
- Per-connection policy `connections.<name>.mint.github_app` in `config.json`: `callers` (default `service` and `host`), `deny_owners`, `allow_owners`, `allow_repos`, `permission_ceiling` and `max_ttl` (1–3600 seconds, default 3600). A connection without the policy cannot mint.
- Audit action `mint` with connection, namespace, repository, permissions, `expires_at`, caller kind and, on failure, the reason. The token is never recorded.
- The deny corpus covers environment and history managers: `direnv exec <dir> env`, `direnv export`, `direnv dump`, `mise env`, `mise exec -- env`, a bare `mise set`, `atuin search`, `atuin history`, and reads of `~/.*_history` and `~/.local/share/atuin`.

### Security

- `keylatch mint` refuses agent sessions, and the mint policy is read only from the operator's default config file (owner-only, not writable by group or others), never from `KEYLATCH_CONFIG` or other overrides. Caller, owner, repository, permission and lifetime checks all run before the key is read, and minting refuses to start without a working audit log.
- GitHub's reply must name only the requested repository, grant exactly the requested permissions and expire within `max_ttl`; otherwise the token is revoked with `DELETE /installation/token` and mint fails. A token whose audit line cannot be written is revoked too.

### Fixed

- The Claude Code exfiltration guard allows `env` when it runs a command (`env -C /abs/dir cmd`, `env NAME=value cmd`, `env -i`, `env -u NAME`). Bare `env`, `env` with no command, other `env` options (`-0`, `-S`, …), a relative `-C` directory and `printenv` stay blocked, and the command after `env` is checked like any other.
- Every shipped agent guard now denies with exit 2 plus the harness's deny JSON (exit 1 does not block in most harnesses). One guard script serves Claude Code, Codex, Gemini CLI, Cursor, Windsurf, Copilot and Antigravity; the hook command selects the stdin payload and deny contract with `--harness <id>`. Re-run `keylatch install-guard <agent>` to pick it up.
- The Cursor installer writes `~/.cursor/hooks.json` (`beforeShellExecution`, fail-closed) instead of `settings.json`; the Codex and Gemini installers write the nested matcher-group schema their harnesses read; Copilot gets a native `PreToolUse` hook in `~/.copilot/hooks/` instead of a shell wrapper.
- Windsurf and Antigravity have hook APIs: `keylatch install-guard windsurf|antigravity` now installs a hook.

### Removed

- The Aider guard installer: Aider has no hook API. Use `keylatch launch -- aider`.

## [0.9.9] - 2026-10-05

### Added

- `keylatch launch [--harness <name>] -- <command>` starts an agent harness with a signed session ticket bound to the launcher process; every process below it is treated as an agent session.
- `keylatch doctor --json` reports `agent_session.detected`, `agent_session.signals` and `agent_session.harness`.

### Security

- The gateway's `/approve/` and `/approvals` routes are removed. Approvals and denials need a terminal, no detected agent session and the approver passphrase (`keylatch approve init`). They are signed with a key derived from that passphrase, and unsigned or tampered approvals are rejected. Approval tokens are validated strictly and confined to the approvals directory.
- Approval decisions sign exactly the reviewed request, display strips control characters, requests are capped at one hour, approvals are single-use within 15 minutes (verification is hardened ahead of enablement), and every `/approve*` path returns 404.
- The untrusted-write gate ignores caller-supplied approval headers.
- Unverified session claims (`KEYLATCH_LLM_TICKET`, an unanswered daemon socket, `KEYLATCH_ALLOW_UNVERIFIED_SESSION`) no longer open raw-credential access, and `allow_unverified_session` is read only from the user's own default config file.
- Audit rotation no longer recurses past the size cap, and it keeps 20 numbered generations. The `keylatchd` retention sweep deletes only rotated audit logs.
- The audit logger finds the keyring bootstrap creates, so audit is on right after bootstrap.
- `gateway up`, `set` and `list --raw` require a working audit log, and the broker and vault refuse secret operations that cannot be audited.
- The gateway forwards an allowlist of request headers and redacts decoded responses; unsupported encodings are refused.
- Bitwarden and 1Password backends pass secret values on stdin, never on the command line, and 1Password writes are verified.
- Team invites, org policy and registry bundles are signed with Ed25519, and unsigned or legacy bundles are refused.
- Admins can no longer take ownership. Role changes and invites cannot grant owner or a role at or above the caller's, duplicate member IDs are refused, and joining keeps an existing team. Team membership changes are disabled until authenticated member identity ships. Registry rollbacks and unpinned org policy are refused.
- The admin handler takes the role from the authenticated session only (hardened ahead of enablement).
- Masking redacts credential-named fields, name/value pairs, `KEY=value` lines, XML elements, PEM keys and URL passwords in every format; strict masking covers `password` and standard base64; untrusted content is never returned unprocessed.
- `grant create` needs a human terminal and caps TTL at 30 days; agent-issued grants are ignored; grant scope matching is hardened ahead of enablement.
- Sandbox mounts cannot expose Keylatch state, and deny paths are enforced or the sandbox refuses to start.
- The broker's cached credentials stay independent of the results it returns.
- v0.9.7 was published without cosign signatures, SBOMs or SLSA provenance while the docs said every artifact was signed. See the [v0.9.7 advisory](docs/security/advisory-v0.9.7-unsigned-release.md); the docs now state what each release carries.
- Releases are created as drafts and published only after every archive, the checksums file, both SBOMs and the release manifest are cosign-signed and SLSA provenance covers every archive. Homebrew and Scoop are updated afterwards, from the signed checksums, and never for pre-releases.
- Release tags must point at a commit on `main` whose required checks passed.
- New `attest-release.yml` workflow rebuilds a published release from its tag and either signs and attests it or marks it unverified.
- syft and trivy are downloaded at pinned versions and verified against committed SHA-256 digests instead of piping install scripts to `sh`; goreleaser is pinned.
- Agent detection also walks the process ancestry: a process started below a harness executable (`claude`, `codex`, `cursor-agent`, `gemini`, `opencode`, `aider`, `copilot`) is an agent session even with its environment cleared.
- No environment variable relaxes a decision any more: `KEYLATCH_ALLOW_UNVERIFIED_SESSION` is removed, and the presence of a session ticket no longer opens raw-credential paths. Only `allow_unverified_session` in the user's own default `config.json` does.

### Changed

- `keylatch doctor` check names drop their internal prefixes: `bootstrap.keyring`, `bootstrap.config` and `plaintext_retention`.
- `keylatch scope` no longer prints a milestone line, and its JSON output no longer has a `Milestone` field.
- The release check scripts moved from `release-gates/` to `release-checks/`.
- CI runs `release-checks/naming-scan.sh`, which rejects internal work-item labels and finding ids in file names, code, docs and commit subjects.
- Harness signals come from one table (`internal/harness`); `keylatch env` lists every one, and actor inference names Cursor, Gemini CLI, OpenCode and Aider sessions. `KEYLATCH_AGENT_SESSION=1` is the documented manual label.
- `keylatch setup` names the agent signals it detected and no longer suggests unsetting them.

### Known limitations

- The bwrap sandbox (not enabled in production) still shares the host PID namespace and `/proc`, passes credentials with `--setenv` and skips deny paths no mount covers; fix before enabling it.
- The approver public key lives in the user-writable config directory; pin it elsewhere before approvals are consumed.
- The audit log assumes a single writer, and a failed restore after rotation starts a new chain.
- `migrate cipher` is not crash-safe per version; back up the vault first.

### Removed

- `keylatchd --llm-session-socket`, `KEYLATCH_DAEMON_SOCKET` and `KEYLATCH_LLM_TICKET`: nothing registered sessions with the daemon, and the query used the CLI's own PID.

### Fixed

- Every CLI error is printed once, never with flag values, and keeps its exit code.
- `migrate cipher` re-encrypts every stored version.
- Policy commands work without a policy file.
- `setup` in reference mode works on a fresh install.
- `keylatch gateway up` now reads credentials from the configured backend. It used to start without a vault and forward credentialed requests upstream with no credential; it now fails at startup when the backend is unusable, and the gateway answers 503 `vault_not_configured` for a credentialed route without a vault.
- The sidecar IPC socket is created owner-only without changing the process umask, which could leave files created concurrently by other goroutines unreadable.

## [0.9.7] - 2026-08-11

### Security

- Gateway request handling now evaluates a real request policy (`internal/policy`) at Step 6 instead of an unconditional pass-through. When `keylatch gateway up` is started with a configured policy file, matching rules are enforced and violations are denied (403 `policy_denied`) with an audit event; requests requiring approval (`rule.Approval`/`ApprovalRootReq`) are denied (403 `policy_approval_required`) since the gateway has no synchronous approval mechanism. Operators who have never configured a policy see no behavior change (pass-through allow is preserved).
- `keylatch doctor`'s 1Password auth checks (`backend.op.auth`, `external.op`) previously reported OK based only on `OP_SERVICE_ACCOUNT_TOKEN` being non-empty (`backend.op.auth`) or `op --version` succeeding (`external.op`) — neither actually confirmed the token/session authenticates. A revoked or expired token reported a false OK. Both checks now run `op whoami --format=json` and report failure/warn on a non-zero exit.
- `keylatch gateway down` sent SIGTERM to whatever process currently held the gateway's PID with no identity verification — unlike `gateway up --force`, which refuses to act on an unverified/mismatched PID. A stale PID file (confirmed to occur in practice) could cause `gateway down` to signal an unrelated process. `down` now runs the same process-identity verification as `up`: a confirmed mismatch is treated as a stale PID (cleaned up, nothing signaled); inconclusive evidence refuses by default (new `--force` to override), rather than guessing.

### Fixed

- `bw`/`op`/`keeper`/`lastpass`/`proton-pass` backends could report a cryptic `"unexpected end of JSON input"` instead of actionable unlock/signin guidance when the CLI exits 0 with empty stdout (a locked vault or expired session that does not always surface as a non-zero exit). All five backends' `Get`/`List` (and bw's `resolveFolderID`) now detect empty stdout before decoding and return the same locked/auth-failure guidance already used for non-zero exits.
- `keylatch setup`'s backend-setup step (`[2/5]`) silently configured `bw` and `op` with zero readiness validation — unlike `keychain`, which already verified/initialized before proceeding. A locked Bitwarden vault or signed-out 1Password session would sail through setup and only surface as a confusing failure at step 4 (connect provider). `bw` now prompts to unlock and caches a session inline; `op` checks auth readiness and warns clearly if not signed in. Both fall back to the encrypted file backend on decline/failure, matching the existing `keychain` UX. Scoped to fresh/changed backend selection only — resuming setup with an already-configured, unchanged backend is unaffected.
- `keylatch connect custom` could silently orphan a stored secret: the connection-metadata write (needed for `list`/`doctor` to recognize the connection) had its error discarded, so a failure there left the secret stored-but-invisible while `connect` still reported success. The metadata write's error is now checked, with rollback of the just-stored secret on failure.

### Changed

- `keylatch trust` is now marked experimental in its help text. `trust enroll <type>` (all five root types) and `trust approve <challenge-id>`'s signing step are unimplemented hardware-root ceremonies — they are hidden from `trust --help`, still directly runnable, and now exit with a distinct code (`NotImplemented`, 10) and a message pointing at this entry and `docs/experimental.md`, instead of a generic error. `trust list`, `trust doctor`, and `trust challenge` remain fully functional and visible. `docs/cli-reference.md`'s `keylatch trust` section previously documented commands that do not exist (`trust status`, `trust add`, `trust remove`) — corrected to match the real command surface.

## [0.9.5] - 2026-07-31

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
- **Claude Code exfiltration guard hardened against command-boundary and tokenizer bypasses** (`contrib/agent-guards/claude-code/block-keylatch-exfiltration.sh`, mirrored at `internal/guard/scripts/block-keylatch-exfiltration.sh`). Closed a quote-wrapped command-boundary bypass (a `bash -c '...'` / `sh -c "..."` wrapper previously evaded detection of `keylatch get`, `security find-*-password`, `op read`/`item get`, `bw get`/`list`, `keylatch run -- env`, and reads of `.keylatch`/`.env` files). Rewrote bare `env`/`printenv` detection from a regex to a structural shell-word tokenizer, closing several further bypass classes (bundled `-c` flag clusters, backslash-newline continuation inside both unquoted and double-quoted text, bare ANSI-C `$'...'` quoting, brace expansion, and positional-parameter default expansion). `keylatch-hook-version` is now `4` — installations should re-run `keylatch install-guard claude-code` to pick up the fix.
- **Aider, Copilot, Cursor, and Windsurf exfiltration guards hardened to match Claude Code's v4 guard.** Bare `env`/`printenv` invocations and `keylatch run -- env` were not detected by these four guards, letting an agent dump loaded secrets via a plain environment listing instead of a flagged read command. Ported the structural `env`/`printenv` tokenizer and the quote-wrapped command-boundary fix into all four guards and their `go:embed`'d `internal/guard/scripts/*-guard.sh` copies. `keylatch-hook-version` is now `3` for these guards — re-run `keylatch install-guard <agent>` to pick up the fix.
- Bumped `google.golang.org/grpc` v1.80.0 → v1.82.1 (GO-2026-6061), `golang.org/x/text` v0.37.0 → v0.39.0 (GO-2026-5970, infinite loop on invalid input), and the Go toolchain 1.26.4 → 1.26.5 (GO-2026-5856, Encrypted Client Hello privacy leak in `crypto/tls`) — all three were reachable from `keylatch`'s TLS proxy and cloud-backend code paths per `govulncheck`.

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
