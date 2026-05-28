# Registry Bundle Signing

> Architecture decision: [ADR-001-cosign-keyless-templates](decisions/ADR-001-cosign-keyless-templates.md)

Provider template bundles (community JSON archives) are cosign-signed before publication
and verified at runtime by the registry loader. EPIC-08 introduced **keyless OIDC signing**
as the default, with keyed ECDSA-P256 signing available as an opt-in for environments
that cannot use OIDC.

---

## Signing modes

### Keyless OIDC (default)

Uses [Sigstore Fulcio](https://docs.sigstore.dev/certificate_authority/overview/) to issue
an ephemeral certificate bound to the GitHub Actions OIDC identity of the publishing
workflow, and records the signing event in the
[Rekor](https://docs.sigstore.dev/logging/overview/) transparency log.

**Output files per bundle:**

| File | Contents |
|------|----------|
| `<bundle>.json.sig` | Detached signature |
| `<bundle>.json.cert` | Ephemeral Fulcio certificate (PEM) |

**Signing identity:**

```
https://github.com/keylatch/keylatch/.github/workflows/publish-registry.yml@refs/heads/main
```

**OIDC issuer:** `https://token.actions.githubusercontent.com`

**CI requirement:** the `publish-registry.yml` workflow must have `id-token: write` in
its permissions block (already set in EPIC-08).

### Keyed ECDSA-P256 (opt-in)

Uses a long-lived key pair. Activate with `REGISTRY_COSIGN_USE_KEYED=1`.

**Output files per bundle:**

| File | Contents |
|------|----------|
| `<bundle>.json.sig` | Detached signature |

(No `.cert` file — the verifier falls back to the embedded `cosign.pub` when `.cert` is absent.)

**Key location:** `internal/registry/cosign.pub` (committed; used by the runtime verifier)

**Secrets:** `REGISTRY_COSIGN_PRIVATE_KEY` (PEM content) and `REGISTRY_COSIGN_PASSWORD` in
GitHub Actions secrets.

---

## Verification

### Keyless — CLI

```bash
cosign verify-blob \
  --certificate dist/provider-bundles/community.json.cert \
  --signature dist/provider-bundles/community.json.sig \
  --certificate-identity-regexp="https://github.com/keylatch/keylatch/.github/workflows/publish-registry.yml@refs/heads/main" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  dist/provider-bundles/community.json
```

### Keyed — CLI

```bash
cosign verify-blob \
  --key internal/registry/cosign.pub \
  --signature dist/provider-bundles/community.json.sig \
  dist/provider-bundles/community.json
```

### Release gate

The `release-gates/registry-signature-verify.sh` script verifies all bundles in a
directory. It automatically selects the verification mode based on `REGISTRY_COSIGN_USE_KEYED`.

```bash
# Keyless (default):
bash release-gates/registry-signature-verify.sh dist/provider-bundles

# Keyed:
REGISTRY_COSIGN_USE_KEYED=1 bash release-gates/registry-signature-verify.sh dist/provider-bundles
```

---

## Runtime verification (`internal/registry/verify.go`)

`LoadBundle` detects the signing mode at runtime by checking for the presence of a
`.cert` file adjacent to the `.sig` file:

| Files present | Verification path |
|---------------|-------------------|
| `.sig` + `.cert` (non-empty) | Keyless: delegates to `cosign verify-blob` subprocess |
| `.sig` only (no `.cert`) | Keyed: ECDSA-P256 against embedded `cosign.pub` |
| Neither | `ErrUnsignedRegistryBundle` |

The subprocess approach for keyless verification keeps behaviour consistent with what
operators run manually and avoids direct Rekor/Fulcio network dependencies in the Go
binary itself.

The expected OIDC identity and issuer are hardcoded as package-level constants
(`registryCosignIdentityRegexp`, `registryCosignOIDCIssuer`) so any change in the
signing workflow is caught by the constant-value test
`TestRegistryVerify_KeylessIdentityConstants`.

---

## Keyed key rotation policy

When using `REGISTRY_COSIGN_USE_KEYED=1`:

1. Generate a new key pair:
   ```bash
   cosign generate-key-pair
   ```
2. Update `REGISTRY_COSIGN_PRIVATE_KEY` and `REGISTRY_COSIGN_PASSWORD` in GitHub
   Actions secrets.
3. Replace `internal/registry/cosign.pub` and commit.
4. Re-sign bundles for all currently-supported releases.
5. Recommended rotation interval: **12 months** or immediately on suspected compromise.

---

## Local signing (keyed, from macOS Keychain)

```bash
# Store once (delete key file after):
security add-generic-password -s "keylatch-bundle-signing" -a "cosign-key" \
  -w "$(cat cosign.key)"
security add-generic-password -s "keylatch-bundle-signing" -a "cosign-passphrase" \
  -w "your-passphrase"
rm cosign.key

# Sign (key never written to disk):
REGISTRY_COSIGN_PRIVATE_KEY=$(security find-generic-password \
  -s "keylatch-bundle-signing" -a "cosign-key" -w) \
REGISTRY_COSIGN_PASSWORD=$(security find-generic-password \
  -s "keylatch-bundle-signing" -a "cosign-passphrase" -w) \
REGISTRY_COSIGN_USE_KEYED=1 \
bash scripts/sign-provider-bundle.sh dist/provider-bundles/
```

---

## Related

- [docs/security.md](../security.md) — security model overview, cross-reference to this doc
- [ADR-001](decisions/ADR-001-cosign-keyless-templates.md) — decision record
- [release.yml](../../.github/workflows/release.yml) — binary keyless signing (reference implementation)
- [publish-registry.yml](../../.github/workflows/publish-registry.yml) — bundle signing CI
