# Security

Until v0.11.0, Keylatch keeps keys out of model context and out of casual agent reach. The broker
daemon that makes keys unreachable arrives in v0.11.0. Today everything runs in **in-user mode**:
the vault, its key-encryption key and the audit log belong to your own user account, so the
protections below make access by an agent hard and visible but are not a boundary against an agent
running as you. See the [threat model](security/threat-model.md) for what each mode protects and
what remains open.

## Security model

Credential values should never appear in model context, agent logs, or MCP tool outputs. Three
layers work toward that:

1. **Agent session detection.** Signals are checked before every value-bearing operation. Each
   signal can only make a decision stricter; a missing or invalid signal changes nothing.

   | Signal | Description |
   |--------|-------------|
   | Environment variables | Variables the harnesses set in the shells they spawn: `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT` (Claude Code); `CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED` (Codex CLI); `CURSOR_AGENT`, `CURSOR_TRACE_ID` (Cursor); `GEMINI_CLI` (Gemini CLI); `OPENCODE` (OpenCode). Also the manual labels `KEYLATCH_AGENT_SESSION` and `CREDENTIALS_LLM_SESSION`, and the legacy aliases `CLAUDE_CODE`, `CODEX_ENV`, `CURSOR_SESSION`, `AIDER_SESSION`, `GEMINI_SESSION`, `OPENCODE_SESSION`. |
   | Process ancestry | A process whose ancestors include a harness executable (`claude`, `codex`, `cursor-agent`, `gemini`, `opencode`, `aider`, `copilot`) is an agent session, even with every variable removed. |
   | Session ticket | `keylatch launch -- <harness>` starts the harness with a signed `KEYLATCH_SESSION_TICKET` bound to the launching process. Every process below it is an agent session. A forged, expired or copied ticket is rejected and logged. |

   **Detection is a label, not a boundary.** A same-user agent can hide every signal: it can run
   outside a harness's process tree or clear its environment. Treat detection as a convenience that
   keeps well-behaved agents on the brokered path. `keylatch approve` and `keylatch deny` also
   refuse to run unless stdin is an interactive terminal; an agent that can allocate a
   pseudo-terminal can still defeat that check. The durable fix is a broker that runs outside the
   agent's user account and requires proof of human presence for privileged operations.

2. **Runtime mode guard.** `keylatch run` has three modes: `gateway_typed` and `gateway_sdk` are
   supported, and `gateway_proxy` is not available in this release. See
   [Runtime modes](runtime-modes.md).

3. **Gateway isolation.** In every gateway mode, agent processes receive only a short-lived
   Keylatch session token and a gateway URL. The gateway validates actor, capability and TTL before
   it resolves a credential, and sends the provider key only to the allowlisted provider. The key
   never returns to the agent, the UI, an MCP response, the logs or the child-process environment.

## Encrypted at rest

| Backend | Encryption |
|---------|-----------|
| `file` | XChaCha20-Poly1305. The key-encryption key is held in the OS keyring when one is available; otherwise it is a plaintext file next to the vault (`keylatch doctor` reports this). |
| `bw` | The `bw` CLI holds the secrets; Keylatch stores references. |
| `op` | The `op` CLI holds the secrets; Keylatch stores references. |

Community and deprecated backends are listed by `keylatch backend list`. No credential value is
written to disk in plaintext or base64 form by the `file` backend, and a CI scan
(`packaging/ci/scan-no-secret-in-storage.sh`) checks that after every write.

## Audit log

Every read, write, injection and gateway operation is appended to `audit.log` in the Keylatch
config directory (mode `0600`). Events are HMAC-chained so edits are detectable with
`keylatch audit --verify-chain`, and they never include secret values. The event types are:

| Group | Events |
|-------|--------|
| Secrets | `write`, `read`, `delete`, `list`, `decrypt`, `encrypt`, `revoke`, `rotate` |
| Keyring | `keyring_init`, `kek_rotate`, `term_destroy` |
| Audit log | `audit_rotate`, `audit_verify`, `audit_read` |
| Policy and tokens | `policy_check`, `token_issue`, `token_revoke` |
| Gateway | `gateway_call`, `gateway_token_mint`, `gateway_token_revoke`, `substitution_blocked` |
| Brokered runs | `broker.exchange`, `broker.cache_hit`, `broker.direct_run_credential_access`, `broker.direct_run_blocked` |
| Child environment | `child_env.filter`, `child_env.clean`, `canary.injected` |
| Bindings | `binding.created`, `binding.widened`, `binding.narrowed`, `binding.refused` |
| Placeholders and proxy | `placeholder.misuse`, `proxy.substituted`, `proxy.session`, `egress.denied` |
| Minting and keys | `mint`, `key.operation`, `key.policy_change` |
| Runs and approvals | `run.decided`, `run.exited`, `approval.requested`, `approval.granted`, `approval.denied` |

```bash
keylatch audit                 # summary of the log
keylatch audit --verify-chain  # check the hash chain
keylatch audit --json          # machine-readable
```

## Gateway security middlewares

The local gateway enforces three middlewares on all proxy routes:

- **`authBlockerMiddleware`** strips agent-supplied `Authorization` replacement attempts. The gateway
  consumes the Authorization header as the Keylatch session JWT and strips it before forwarding; the
  handler injects the real provider credential internally.
- **`hostOverrideBlockerMiddleware`** blocks `X-Forwarded-Host`, `X-Original-URL` and
  `X-Rewrite-URL` headers that could redirect upstream traffic to attacker-controlled hosts.
- **`SSRFGate`** blocks SSRF-class upstream destinations (loopback, link-local, metadata endpoints)
  before any outbound connection is made.

## Canary leak detection

Canary sentinel values are injected at test time to verify no credential escapes into logs,
stdout, stderr or generated files, in three test layers: unit canary tests on every CLI path that
handles a credential, a meta test that checks `canary.AssertNoLeak` is called everywhere it must
be, and end-to-end tests that build the CLI binary. CI also runs a static grep (`security.yml`)
that catches a canary string leaking outside `internal/canary/` into production code.

## Agent exfiltration guard

`keylatch install-guard claude-code` writes a `PreToolUse` hook that blocks agent commands which
try to read the vault, the config directory or backend sessions directly. In v0.10.0 the guard
supports Claude Code only. The other harnesses are detected but get their guard in v0.13.0. The
hook is tested on Ubuntu and macOS runners in CI, and `keylatch doctor` reports whether it is
installed, current and covers every tool.

## Artifact signing

A release is published only after its CLI archives, the checksums file, both SBOMs and the
release manifest are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) via GitHub
Actions OIDC (keyless signing) and SLSA provenance covers every archive. No long-lived signing
keys are stored. **v0.9.7 was published without any of these**; see the
[v0.9.7 advisory](security/advisory-v0.9.7-unsigned-release.md). [How signing works](architecture/signing.md)
describes the model, and [Verifying releases](verifying-releases.md) lists what each release
carries and the verification commands.

## Provider template signing

Provider template bundles are signed with cosign (keyless by default; keyed ECDSA-P256 is opt-in
with `REGISTRY_COSIGN_USE_KEYED=1`). See [Registry bundle signing](architecture/registry-signing.md)
for verification commands and key rotation.

## Cipher suite

Keylatch encrypts with XChaCha20-Poly1305. `keylatch doctor --json` reports it:

```json
{
  "cipher_suite": "xchacha20-poly1305",
  "fips_build": false
}
```

A FIPS-validated build is not available.

## SBOM

Releases from v0.9.0 include a software bill of materials, except v0.9.1, v0.9.2 and v0.9.7;
releases built by the current pipeline ship both SPDX and CycloneDX. Scan for CVEs with
[grype](https://github.com/anchore/grype):

```bash
grype sbom:keylatch-v<version>.spdx.json
```

## Supported versions

| Version | Supported |
|---------|-----------|
| v0.10.0 and later: the latest minor release | Yes, all bug and security fixes |
| v0.10.0 and later: the previous minor release | Security fixes only |
| Anything before v0.10.0 | No |

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/keylatch/keylatch/blob/main/SECURITY.md) for the disclosure
policy and contact details.

**Do not open a public GitHub issue for security vulnerabilities.**
