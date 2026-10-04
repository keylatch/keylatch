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

The signing job itself did run. In the same workflow run it signed every archive, the
checksums file and the CycloneDX SBOM with the release workflow's keyless identity
(`.github/workflows/release.yml@refs/tags/v0.9.7`), and those signatures verify against the
published v0.9.7 assets. They were kept only as workflow artifacts and never attached to the
release, so nobody downloading v0.9.7 could check them. The SLSA provenance from that run was
not kept.

There is no evidence that any v0.9.7 artifact was modified.

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

## Remediation of the v0.9.7 release

- The signatures and SBOMs from the original release run are attached to the v0.9.7 release
  once they are verified against the published files. Check the release page for `.sig` and
  `.pem` files before relying on them.
- The attest workflow then rebuilds v0.9.7 from its tag. If the digests match, it adds the
  SPDX SBOM signature and SLSA provenance, signed with the identity
  `.github/workflows/attest-release.yml@refs/heads/main`.
- If no valid signature is attached and the rebuild does not match, v0.9.7 is marked
  unverified and loses "Latest". Homebrew and Scoop are then pointed at v0.9.5 until v0.9.8 is
  out.
