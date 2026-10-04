# Advisory: v0.9.7 was published without signatures, SBOMs or provenance

| | |
|---|---|
| **Affected** | Keylatch v0.9.7 release assets on GitHub, and the v0.9.7 Homebrew formula and Scoop manifest |
| **Published** | 2026-08-18 |
| **Fixed in** | v0.9.8 |
| **Severity** | Low (supply-chain assurance, no known tampering) |

## What happened

The v0.9.7 release workflow created the GitHub release and updated the Homebrew tap and the
Scoop bucket before its signing job ran. The container-image signing job then failed, so the
job that attaches signatures was skipped. The release went out with five archives and
`keylatch-0.9.7_checksums.txt` only:

- no cosign `.sig` or `.pem` files;
- no CycloneDX or SPDX SBOM;
- no SLSA provenance.

At the same time `README.md`, `SECURITY.md` and `docs/verifying-releases.md` said every
release artifact is signed. That statement was false for v0.9.7.

There is no evidence that any v0.9.7 artifact was modified. The problem is that you cannot
prove where it came from: the checksums file only shows that a download was not corrupted.

## What changed

- A release is created as a draft and becomes public only after every archive, the checksums
  file, both SBOMs and the release manifest carry a verified keyless cosign signature and the
  SLSA provenance covers every archive. Any missing file fails the release.
- Homebrew and Scoop are updated only after that, from a release whose checksums signature
  verifies.
- Releases are cut only from tags whose commit is on `main` and has passed the required checks.
- A separate workflow rebuilds a published release from its tag and compares digests. If they
  match, it signs the published files and attaches SBOMs and provenance. If not, the release
  is marked unverified and loses "Latest".

## What to do

- **Homebrew:** `brew update && brew upgrade keylatch` once v0.9.8 is out.
- **Scoop:** `scoop update keylatch` once v0.9.8 is out.
- **Direct downloads:** replace v0.9.7 with v0.9.8 and verify it as described in
  [Verifying releases](../verifying-releases.md).
- **Until then:** v0.9.5 is the most recent release with signatures and provenance.

If the v0.9.7 rebuild matches the published digests, its assets gain signatures, SBOMs and
provenance from the attest workflow. The certificate identity is then
`.github/workflows/attest-release.yml@refs/heads/main` rather than the tag-triggered release
workflow.
