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

Releases built by the current release workflow are published only after every CLI archive,
the checksums file (`keylatch-<version>_checksums.txt`), both SBOMs and the release manifest
carry a keyless [cosign](https://docs.sigstore.dev/cosign/overview/) signature and
certificate, and SLSA provenance covers every archive. Homebrew and Scoop are updated only
after that.

Not every past release meets this bar. **v0.9.7 was published with no signatures, SBOMs or
provenance**; see the [v0.9.7 advisory](docs/security/advisory-v0.9.7-unsigned-release.md).
[Verifying releases](docs/verifying-releases.md) lists what each release carries and how to
verify it:

```bash
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/keylatch/keylatch/\.github/workflows/(release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?|attest-release\.yml@refs/heads/main)$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --certificate keylatch-<version>_checksums.txt.pem \
  --signature keylatch-<version>_checksums.txt.sig \
  keylatch-<version>_checksums.txt
```

## Security Advisories

- [v0.9.7 published without signatures, SBOMs or provenance](docs/security/advisory-v0.9.7-unsigned-release.md)

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
