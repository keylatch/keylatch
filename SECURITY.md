# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Keylatch, please report it privately.

**Do not open a public GitHub issue for security vulnerabilities.**

### Preferred contact

- **Email**: security@keylatch.dev *(GPG key: not yet published — targeted for v1.1; unencrypted reports accepted for now)*
- **GitHub**: Open a [private security advisory](https://github.com/keylatch/keylatch/security/advisories/new) for confidential disclosure

### What to include

- A clear description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept code or commands)
- The version(s) affected
- Any mitigations you have identified

We acknowledge receipt within 2 business days and aim to provide a patch timeline within 7 days.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest minor release | Yes |
| One previous minor release | Yes (security fixes only) |
| Older releases | No |

## Artifact Signing

All release artifacts are signed with [cosign](https://docs.sigstore.dev/cosign/overview/)
via GitHub Actions OIDC (keyless signing). Verify any release artifact with:

```bash
cosign verify-blob \
  --certificate-identity-regexp="github.com/keylatch" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  <artifact> \
  --signature <artifact>.sig
```

`SHA256SUMS` and `SHA256SUMS.sig` are published alongside each release.

## FIPS Build

Non-FIPS builds use `xchacha20-poly1305` (FIND-015 cipher_suite).
A FIPS-compliant build using AES-256-GCM is planned for Phase 11.
Check the `cipher_suite` field in `keylatch doctor --json` to confirm the active cipher.

## Provider Registry Signing

Provider template bundles shipped with Keylatch are cosign-signed (FIND-008).
Signed bundles with separate `.sig` files will ship starting in v1.1.

## Scope

The following are in scope for security reports:

- Credential exfiltration via any output channel (stdout, stderr, logs, temp files)
- Bypassing LLM-session guards (SecurityBlock exit code 2)
- Backend authentication bypass
- Canary token leakage
- Injection of arbitrary commands via provider templates

The following are out of scope:

- Vulnerabilities in third-party credential backends (report to them directly)
- Issues requiring physical access to the machine
- Social engineering attacks
