# Security

## Security model

Keylatch is built on the principle that credential values should never appear in model context, agent logs, or MCP tool outputs. The enforcement stack has three layers:

1. **LLM session detection** — three priority tiers are checked before every value-bearing operation (EPIC-05):

   | Priority | Signal | Description |
   |----------|--------|-------------|
   | 1 | `KEYLATCH_LLM_TICKET` env var | Signed HS256 JWT issued by keylatchd. Presence alone is sufficient to return true (fail-closed fast path). Full verification via `VerifyTicket` is available for callers that need cryptographic proof. |
   | 2 | keylatchd IPC query | If `KEYLATCH_DAEMON_SOCKET` is set, the CLI queries `GET /v1/llm-session?pid=<n>` over a Unix domain socket. Any network error, timeout, or schema mismatch fails closed (returns true). Only a clean `active:false` response from the daemon passes. **Callers must set `KEYLATCH_DAEMON_SOCKET=<socket-path>` in each child process environment for IPC to work — the variable is not automatically propagated.** |
   | 3 | Environment-variable signals | Seven signals: `CLAUDE_CODE`, `CODEX_ENV`, `CREDENTIALS_LLM_SESSION`, `CURSOR_SESSION`, `AIDER_SESSION`, `GEMINI_SESSION`, `OPENCODE_SESSION`. |

   **Fail-closed contract**: any ambiguous or error state returns true (assume LLM session). The only way `IsLLMSession` returns false is when all three tiers produce no signal. Detected sessions block `keylatch get` (exit 2) and restrict the UI to `status-only` scope.

   **Known limitation (v1.0.0)**: IDE extension ticket issuance is out of scope. The `KEYLATCH_LLM_TICKET` env var and `POST /v1/llm-session` endpoint are available for future IDE integrations. Until then, Priority 3 (env-var signals) remains the primary detection mechanism for all supported agents.

2. **Runtime mode guard** — `keylatch run` allows all four v1.0.0 runtime modes (`gateway_typed`, `gateway_sdk`, `direct_brokered`, `gateway_proxy`) in LLM sessions. Raw credential values are never returned to the agent process in any mode.

3. **Gateway isolation** — in gateway modes, agent processes receive only a short-lived Keylatch session token and a gateway URL. The gateway validates actor, capability, and TTL before resolving and forwarding credentials. Provider keys never return to the agent, UI, MCP response, logs, or child-process environment.

## Encrypted at rest

All local credentials are encrypted before storage:

| Backend | Encryption |
|---------|-----------|
| File | XChaCha20-Poly1305 (AES-256-GCM under FIPS build); KEK from platform keyring |
| macOS Keychain | Keychain-native encryption via Security framework |
| 1Password | `op` CLI; KEK derived from passphrase |
| Bitwarden | `bw` CLI; KEK derived from passphrase |

No credential value is ever written to disk in plaintext or base64 form.

### CRIT-01 — AEAD storage (closed, EPIC-03)

**Status: closed** — implemented in EPIC-03 (AEAD Storage).

Prior to EPIC-03 the `file` backend could write credentials as base64-encoded
plaintext. CRIT-01 closed this gap:

- All writes go through XChaCha20-Poly1305 AEAD (or AES-256-GCM under `KEYLATCH_FIPS=1`).
- The base64 write path is removed from `FileBackend.Set` (`T-02-02`).
- `SetVersioned`/`GetVersioned` fail closed without a keyring (`T-02-03`).
- `bootstrap` initializes the platform keyring so the file backend can operate
  without a separate manual setup step (`T-02-04`).
- CI scan (`packaging/ci/scan-no-secret-in-storage.sh`) verifies that neither
  plaintext nor base64 of any credential pattern appears in vault storage after
  any write operation (`T-02-05`, `S-INV-1`).

## Audit log

Every read, write, injection, and gateway operation is appended to `~/.keylatch/audit.log` (mode `0600`). The log is HMAC-chained for tamper resistance. Audit events never include secret values.

```bash
keylatch audit          # view the log
keylatch audit --json   # machine-readable
```

## Gateway security middlewares

The local gateway HTTP server enforces three middlewares on all proxy routes:

- **`authBlockerMiddleware`** — strips agent-supplied `Authorization` replacement attempts. The gateway consumes the Authorization header as the Keylatch session JWT and strips it before forwarding upstream; the handler injects the real provider credential internally.
- **`hostOverrideBlockerMiddleware`** — blocks `X-Forwarded-Host`, `X-Original-URL`, and `X-Rewrite-URL` headers that could redirect upstream traffic to attacker-controlled hosts.
- **`SSRFGate`** — blocks SSRF-class upstream destinations (loopback, link-local, metadata endpoints, etc.) before any outbound connection is made.

## Canary leak detection

Canary sentinel values are injected at test time to verify no credential escapes into logs, stdout, stderr, or generated files. Three test layers:

1. **Unit canary tests** — every CLI path that handles a credential runs canary assertions.
2. **Meta coverage test** — verifies that `canary.AssertNoLeak` is called in every required location.
3. **E2E canary tests** — the CLI binary is built and exercised; canary values must not appear in any output or written file.

CI also runs a static grep (`security.yml`) that catches any canary string that leaks outside `internal/canary/` into production code.

## Agent exfiltration guard

A Claude Code hook script (`contrib/agent-guards/claude-code/block-keylatch-exfiltration.sh`) blocks agent commands that attempt to read the Keylatch vault, keychain, or config directory directly. The hook is tested on ubuntu and macos runners in CI.

## Artifact signing

All release artifacts are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) via GitHub Actions OIDC (keyless signing). No long-lived signing keys are stored.

To verify a release artifact:

```bash
cosign verify-blob \
  --certificate-identity-regexp="https://github.com/keylatch/keylatch/.github/workflows/release.yml" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --signature keylatch-v0.1.0.SHA256SUMS.sig \
  keylatch-v0.1.0.SHA256SUMS
```

The `SHA256SUMS` file lists checksums for every binary and archive in the release.

## Provider template signing

Provider template bundles are cosign-signed before publication and verified by the runtime loader before any template-defined validation or injection executes.

EPIC-08 introduced **keyless OIDC signing** as the default (Fulcio + Rekor), with keyed ECDSA-P256 signing available as an opt-in via `REGISTRY_COSIGN_USE_KEYED=1`. See [Architecture: Registry Bundle Signing](architecture/registry-signing.md) for full details including verification commands, the runtime detection logic, and key rotation policy.

## FIPS compliance

The default release uses XChaCha20-Poly1305 for data-plane encryption. Run `keylatch doctor --json` to confirm:

```json
{
  "cipher_suite": "xchacha20-poly1305",
  "fips_build": false
}
```

A FIPS-validated build (`-tags=fips`) uses AES-256-GCM and forces the Go FIPS crypto provider. Build with:

```bash
go build -tags=fips ./cmd/keylatch
```

## SBOM

Every release includes a software bill of materials (SBOM) in both SPDX and CycloneDX formats. Scan for CVEs with [grype](https://github.com/anchore/grype):

```bash
grype sbom:keylatch-v0.1.0-sbom.spdx.json
```

## Cryptographic test vectors

Release tarballs include `internal/crypto/envelope/testdata/vectors/` and a `vectors.sha256` manifest. The cosign signature covers the full vector set, providing a verifiable chain of custody for cryptographic correctness.

## Supported versions

| Version | Supported |
|---------|-----------|
| Latest minor release | Yes — all bug and security fixes |
| Previous minor release | Security fixes only |
| Older releases | Not supported |

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/keylatch/keylatch/blob/main/SECURITY.md) for the responsible disclosure policy and contact details.

**Do not open a public GitHub issue for security vulnerabilities.**
