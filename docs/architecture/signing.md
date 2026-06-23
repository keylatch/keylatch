# How Keylatch Signing Works

Keylatch uses **three independent signing systems**. They are easy to confuse because
the word "signed" means something different in each. This document explains what each
one is, what it proves, and how it is wired. For step-by-step *verification* commands,
see [Verifying releases](../verifying-releases.md).

## The three systems at a glance

| System | Mechanism | What it signs | What it proves | Status |
|---|---|---|---|---|
| **Release artifact signing** | cosign **keyless** (Sigstore) via GitHub OIDC | CLI archives, `checksums.txt`, SBOM, release manifest, **and desktop installers** (`.dmg`/`.exe`/`.AppImage`/`.deb`) | The artifact was produced by *this* repo's release workflow at a tagged commit (origin + integrity) | **Active** |
| **Provider registry signing** | cosign keyless (default) or keyed ECDSA-P256 (opt-in) | The provider template bundle (`community.json`) | Templates were published by Keylatch before the runtime loads them | **Active** — see [Registry Bundle Signing](registry-signing.md) |
| **OS code-signing** | Apple notarization / Windows Authenticode certificates | The desktop app bundle, recognised by the OS | The OS will launch the app without a Gatekeeper / SmartScreen warning | **Not yet** — certificates not provisioned |

> The **Tauri auto-updater** also has a signing key (`TAURI_SIGNING_PRIVATE_KEY`, minisign),
> used to sign in-app update payloads. It is currently **dormant**: `updater.active` is
> `false` and no updater artifacts are generated. It is unrelated to the three systems
> above and produces nothing in today's releases. It will be enabled with the auto-updater
> in a future release.

## Why cosign keyless needs no secrets

The release pipeline never stores a long-lived signing key. Instead it uses
**Sigstore keyless signing**, which works like this on every tagged release:

1. The workflow is granted an **OIDC identity token** (`permissions: id-token: write`).
   This token encodes *who* is signing: the repo, the workflow file, and the tag —
   e.g. `https://github.com/keylatch/keylatch/.github/workflows/release.yml@refs/tags/v0.9.3`.
2. cosign exchanges that token with **Fulcio**, Sigstore's certificate authority, which
   issues a **short-lived (≈10 min) signing certificate** bound to that identity.
3. cosign signs the artifact with the certificate's ephemeral private key, then **throws
   the key away**.
4. The signature + certificate are recorded in **Rekor**, Sigstore's public, tamper-evident
   transparency log.

Because the identity is baked into the certificate, verification doesn't need a public key —
it needs the **expected identity**. That is why every verify command pins both:

```
--certificate-identity-regexp="^https://github\.com/keylatch/keylatch/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$"
--certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```

A signature only verifies if it was produced by **that workflow, in this repo, on a release
tag** — a forged or tampered artifact cannot satisfy it, and the Rekor log makes after-the-fact
tampering detectable.

## What gets signed in the release pipeline

All of this lives in [`.github/workflows/release.yml`](../../.github/workflows/release.yml):

| Job | Signs |
|---|---|
| `cosign-sign` | CLI archives (`*.tar.gz`, `*.zip`), `*_checksums.txt`, and the SBOM (`*.cdx.json`) |
| `manifest` | The JSON release manifest |
| `publish` | The desktop installers (`.dmg`, `*-setup.exe`, `.AppImage`, `.deb`) — signed and re-verified before upload |

Each signed file ships with an adjacent `.sig` (signature) and `.pem` (certificate). The
`publish` job inherits `id-token: write`, so desktop signing is keyless too — no certificate
or password secret is involved.

> **Note:** Desktop installer cosign signatures were added alongside the desktop-bundle
> build. CLI archives, checksums, and the SBOM have been cosign-signed since earlier
> releases; desktop installer `.sig`/`.pem` files appear from the first release built with
> this pipeline change onward.

## What cosign does *not* do

cosign proves **origin and integrity** — that a file came from the Keylatch pipeline and
hasn't been altered. It does **not** make the operating system trust the app:

- macOS **Gatekeeper** only trusts apps notarized with an Apple Developer certificate.
- Windows **SmartScreen** only trusts installers signed with an Authenticode (ideally EV)
  certificate.

Neither certificate is provisioned yet, so desktop installers still trigger first-launch
warnings and need the documented workarounds (`xattr` on macOS, "More info → Run anyway" on
Windows). A cosign signature and OS code-signing are **complementary**, not substitutes:
cosign lets a security-conscious tester *verify* the build; OS code-signing removes the
*warning*. You can ship the first without the second — which is exactly today's state.

## Related

- [Verifying releases](../verifying-releases.md) — copy-paste verification commands
- [Registry Bundle Signing](registry-signing.md) — provider template signing (keyless + keyed)
- [Security](../security.md) — overall security model
- [ADR-001: cosign keyless for templates](decisions/ADR-001-cosign-keyless-templates.md)
