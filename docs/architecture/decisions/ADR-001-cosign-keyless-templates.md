# ADR-001: Cosign Keyless Signing for Provider Template Bundles

**Status:** Accepted
**Date:** 2026-05-18
**Epic:** EPIC-08

---

## Context

Keylatch ships provider template bundles (community JSON archives) alongside the CLI.
Until EPIC-08 these bundles were signed with a long-lived ECDSA-P256 key pair:

- Private key stored as a GitHub Actions secret (`REGISTRY_COSIGN_PRIVATE_KEY`).
- Public key committed at `internal/registry/cosign.pub` for runtime verification.
- `sign-provider-bundle.sh` writes only `.sig` files (no certificate chain).
- `verify.go` verifies against the embedded public key.

The binary release pipeline (`release.yml`) already uses **keyless OIDC signing** via
Fulcio + Rekor: `id-token: write` is granted, no private key is stored.

This split creates two trust models within the same repo:

| Artifact | Mode | Key custody |
|----------|------|-------------|
| CLI binary / SHA256SUMS | Keyless (Fulcio + Rekor) | None — ephemeral |
| Provider template bundles | Keyed (ECDSA-P256) | `REGISTRY_COSIGN_PRIVATE_KEY` secret |

The asymmetry adds operational overhead (key rotation, secret management) and a weaker
trust model for bundles: a compromised `REGISTRY_COSIGN_PRIVATE_KEY` cannot be detected
after the fact through Rekor transparency.

---

## Decision

**Default to keyless OIDC signing for provider template bundles**, matching the binary
signing model. Retain keyed signing as an opt-in for environments that cannot use OIDC
(air-gapped runners, forks, local re-signing).

The opt-in flag is the environment variable `REGISTRY_COSIGN_USE_KEYED`:

| Value | Behaviour |
|-------|-----------|
| unset or `0` | Keyless OIDC signing (default) — requires `id-token: write` |
| `1` | Keyed ECDSA-P256 signing — requires `REGISTRY_COSIGN_PRIVATE_KEY` + `REGISTRY_COSIGN_PASSWORD` |

Keyless signing produces two output files per bundle:

- `<bundle>.sig` — detached signature
- `<bundle>.cert` — ephemeral Fulcio certificate (chain of trust)

The presence of a `.cert` file adjacent to a `.sig` file signals the keyless path to
the verifier. When only `.sig` exists, the verifier falls back to keyed verification
against `cosign.pub`.

---

## Alternatives Considered

### Stay keyed only
Simpler verifier (one code path), but retains key custody burden and does not benefit
from Rekor transparency. Rejected: operational cost outweighs simplicity.

### Keyless only — remove keyed path entirely
Cleanest trust model, but breaks forks and any runner without OIDC. Rejected: too
restrictive for community contributors.

### User-choice flag (`--keyless` / `--keyed` CLI arg)
Finer-grained control, but adds CLI surface and complicates CI matrix. The env-var
opt-in achieves the same without API churn. Rejected: over-engineered for current needs.

---

## Consequences

**Positive**

- No private key to rotate or protect for the default path.
- Every signing event appears in the Rekor public transparency log — tamper-evident
  by design.
- Consistent trust model with binary artifacts: one signing identity for the whole repo
  (`publish-registry.yml@refs/heads/main` vs `release.yml@refs/heads/main`).
- Simpler CI secret surface: `REGISTRY_COSIGN_PRIVATE_KEY` and `REGISTRY_COSIGN_PASSWORD`
  only required for keyed opt-in.

**Negative / trade-offs**

- GitHub Actions runners without OIDC capability (forks, some enterprise policies)
  must set `REGISTRY_COSIGN_USE_KEYED=1` and provision the key secrets.
- Keyless verification requires network access to Rekor during `cosign verify-blob`;
  air-gapped environments must use keyed path.
- Verifier now has two code paths; each requires test coverage.

**Rotation policy (keyed path)**

When `REGISTRY_COSIGN_USE_KEYED=1` is active:

1. Generate a new key pair with `cosign generate-key-pair`.
2. Update `REGISTRY_COSIGN_PRIVATE_KEY` and `REGISTRY_COSIGN_PASSWORD` in GitHub
   Actions secrets.
3. Replace `internal/registry/cosign.pub` with the new public key and commit.
4. Re-sign all bundles in the last N releases that are still in-support.
5. Recommended rotation interval: 12 months or on any suspected compromise.

---

## Implementation Notes

- `publish-registry.yml`: add `id-token: write`; gate signing steps on
  `REGISTRY_COSIGN_USE_KEYED`.
- `scripts/sign-provider-bundle.sh`: branch on `${REGISTRY_COSIGN_USE_KEYED:-0}`;
  keyless path passes `--output-certificate`.
- `internal/registry/verify.go`: detect `.cert` file → keyless verify path using
  `cosign verify-blob --certificate`; else → keyed path.
- `release-gates/registry-signature-verify.sh`: test both paths with fixtures.
- `docs/architecture/registry-signing.md`: operator reference for both modes.

---

## References

- [Sigstore cosign keyless signing](https://docs.sigstore.dev/cosign/signing/keyless/)
- [Rekor transparency log](https://docs.sigstore.dev/logging/overview/)
- `release.yml` — existing keyless binary signing (reference implementation)
- `internal/registry/verify.go` — current keyed verifier
