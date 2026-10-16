# Security Policy

## What Keylatch protects, and what it does not

Until v0.11.0, Keylatch keeps keys out of model context and out of casual agent reach. The
broker daemon that makes keys unreachable arrives in v0.11.0.

Today Keylatch runs in **in-user mode**: the vault, its key-encryption key and the audit log live
under your own user account. The agent exfiltration guard, the LLM-session checks and the policy
make direct access by an agent hard and visible. They are **not a security boundary**: an agent
that runs as you can still read files you own, use credentials your shell exports, and call the
tools your shell can call. [docs/security/threat-model.md](docs/security/threat-model.md) states
the protection each mode gives and the risks that remain.

## Reporting a Vulnerability

If you discover a security vulnerability in Keylatch, please report it privately.

**Do not open a public GitHub issue for security vulnerabilities.**

### Preferred contact

- **Email**: security@keylatch.dev *(no PGP key is published yet; unencrypted reports are accepted)*
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
| v0.10.0 and later: the latest minor release | Yes |
| v0.10.0 and later: the one previous minor release | Yes (security fixes only) |
| Anything before v0.10.0 | No |

## Artifact Signing

Releases built by the current release workflow are published only after every CLI archive
(`keylatch_<version>_<os>_<arch>.tar.gz`, or `.zip` on Windows), the checksums file
(`keylatch-<version>_checksums.txt`), both SBOMs and the release manifest carry a keyless
[cosign](https://docs.sigstore.dev/cosign/overview/) signature and certificate, and SLSA
provenance covers every archive. Homebrew and Scoop are updated only after that.

Not every past release meets this bar. **v0.9.7 was published with no signatures, SBOMs or
provenance**; see the [v0.9.7 advisory](docs/security/advisory-v0.9.7-unsigned-release.md).
[Verifying releases](docs/verifying-releases.md) lists what each release carries and how to
verify it. To check the checksums file of version `<version>` (without the leading `v`):

```bash
cosign verify-blob \
  --certificate-identity-regexp '^https://github\.com/keylatch/keylatch/\.github/workflows/(release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?|attest-release\.yml@refs/heads/main)$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --certificate keylatch-<version>_checksums.txt.pem \
  --signature keylatch-<version>_checksums.txt.sig \
  keylatch-<version>_checksums.txt
```

Then check the archive against the verified checksums file:

```bash
sha256sum --check --ignore-missing keylatch-<version>_checksums.txt
```

## Security Advisories

- [v0.9.7 published without signatures, SBOMs or provenance](docs/security/advisory-v0.9.7-unsigned-release.md)

## Cipher suite

Keylatch encrypts with `xchacha20-poly1305`. `keylatch doctor --json` reports the active
`cipher_suite`. A FIPS-validated build is not available.

## Provider Registry Signing

Provider template bundles shipped inside the binary are covered by the release signature. Signed
bundles with separate `.sig` files are not published yet.

## Scope

The following are in scope for security reports:

- Credential exfiltration via any output channel (stdout, stderr, logs, temp files)
- Bypassing the agent guards or the LLM-session checks (exit code 2)
- Backend authentication bypass
- Canary token leakage
- Injection of arbitrary commands via provider templates

The following are out of scope:

- Vulnerabilities in third-party credential backends (report to them directly)
- Issues requiring physical access to the machine
- Social engineering attacks
- An agent that runs as your own user reading files you own while Keylatch runs in in-user mode,
  which is a documented limit until the broker daemon ships
