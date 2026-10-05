# Security

## Security model

Keylatch is built on the principle that credential values should never appear in model context, agent logs, or MCP tool outputs. The enforcement stack has three layers:

1. **Agent session detection** — signals checked before every value-bearing operation. Each signal can only make a decision stricter; a missing or invalid signal changes nothing:

   | Signal | Description |
   |--------|-------------|
   | Environment variables | Variables the harnesses set in the shells they spawn: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT` (Claude Code); `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED` (Codex CLI); `CURSOR_AGENT`, `CURSOR_TRACE_ID` (Cursor); `GEMINI_CLI` (Gemini CLI); `OPENCODE` (OpenCode). Also the manual labels `KEYLATCH_AGENT_SESSION` and `CREDENTIALS_LLM_SESSION` and the legacy aliases `CLAUDE_CODE`, `CODEX_ENV`, `CURSOR_SESSION`, `AIDER_SESSION`, `GEMINI_SESSION`, `OPENCODE_SESSION`. |
   | Process ancestry | A process whose ancestors include a harness executable (`claude`, `codex`, `cursor-agent`, `gemini`, `opencode`, `aider`, `copilot`) is an agent session, even with every variable removed. |
   | Session ticket | `keylatch launch -- <harness>` starts the harness with a signed `KEYLATCH_SESSION_TICKET` bound to the launching process. Every process below it is an agent session. A forged, expired or copied ticket is rejected and logged. |

   **Detection is a label, not a boundary.** A same-user agent can hide every signal: it can run outside a harness's process tree or clear its environment. Treat detection as a convenience that keeps well-behaved agents on the brokered path. `keylatch approve` and `keylatch deny` also refuse to run unless stdin is an interactive terminal; an agent that can allocate a pseudo-terminal can still defeat that check. The durable fix is a broker that runs outside the agent's user account and requires proof of human presence for privileged operations.

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

- All writes go through XChaCha20-Poly1305 AEAD (or AES-256-GCM when built with the `-tags=fips` build tag).
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

A release is published only after its CLI archives, the checksums file, both SBOMs, the release manifest and any Linux desktop bundles are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) via GitHub Actions OIDC (keyless signing) and SLSA provenance covers every archive. No long-lived signing keys are stored. **v0.9.7 was published without any of these**; see the [v0.9.7 advisory](security/advisory-v0.9.7-unsigned-release.md). See [How Keylatch signing works](architecture/signing.md) for the full model, and [Verifying releases](verifying-releases.md) for what each release carries and the verification commands.

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

Releases from v0.9.0 on include a software bill of materials (SBOM), except v0.9.1, v0.9.2 and v0.9.7; releases built by the current pipeline always ship both SPDX and CycloneDX. Scan for CVEs with [grype](https://github.com/anchore/grype):

```bash
grype sbom:keylatch-v<version>.spdx.json
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
