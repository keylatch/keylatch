---
title: Installation
description: Install Keylatch on macOS, Windows, Linux, or via Docker.
---

# Installation

## macOS — Homebrew

```bash
brew install keylatch/tap/keylatch
```

## Windows — Scoop

```powershell
scoop bucket add keylatch https://github.com/keylatch/scoop
scoop install keylatch
```

## Linux — install from a release

`installers/install.sh` downloads the archive for your architecture from a published
release, checks its SHA-256 against the release checksums file, verifies that file with
cosign (keyless, GitHub OIDC), and installs `keylatch` and `keylatchd` into a directory you
choose. It needs `curl`, `tar`, `sha256sum` and `cosign`.

```bash
VERSION=X.Y.Z   # a published release, without the leading v
curl -fsSLO "https://raw.githubusercontent.com/keylatch/keylatch/v${VERSION}/installers/install.sh"
bash install.sh --version "${VERSION}" --prefix "$HOME/.local/bin"
```

Fetch the installer from the same tag it installs. Pass `--skip-signature` only if you
cannot install cosign: the checksum then proves integrity but not that the release
pipeline built the archive. Releases are published as drafts and only become visible once
every signature and the provenance are attached, so there is no `latest` shortcut; pin a
version.

### Manual tarball

```bash
VERSION=X.Y.Z
curl -fsSLO "https://github.com/keylatch/keylatch/releases/download/v${VERSION}/keylatch_${VERSION}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/keylatch/keylatch/releases/download/v${VERSION}/keylatch-${VERSION}_checksums.txt"
sha256sum --check --ignore-missing "keylatch-${VERSION}_checksums.txt"
tar -xzf "keylatch_${VERSION}_linux_amd64.tar.gz"
install -m 0755 keylatch keylatchd "$HOME/.local/bin/"
```

Use `arm64` for ARM hosts. [Verifying releases](verifying-releases.md) covers the cosign
and provenance checks.

## Docker

The `keylatch` CLI is available as a minimal image. **It ships only the CLI —
there is no `keylatchd` sidecar binary or desktop shell in the container.**

```bash
docker pull ghcr.io/keylatch/keylatch:latest
```

The image runs as the `nonroot` user (UID 65532, distroless), so credential
and config paths must live under that user's home directory, not `/root`.
Point `KEYLATCH_CONFIG_DIR` at a persisted volume:

```bash
docker run --rm \
  -e KEYLATCH_CONFIG_DIR=/home/nonroot/.keylatch \
  -v keylatch-data:/home/nonroot/.keylatch \
  ghcr.io/keylatch/keylatch:latest doctor --json
```

To use the browser UI, opt in to a non-loopback listen address explicitly and
publish the port — the entrypoint requires a subcommand (running the image
with no subcommand just prints `--help` and exits):

```bash
docker run --rm \
  -e KEYLATCH_CONFIG_DIR=/home/nonroot/.keylatch \
  -v keylatch-data:/home/nonroot/.keylatch \
  -e KEYLATCH_UI_LISTEN=0.0.0.0:7890 \
  -p 7890:7890 \
  ghcr.io/keylatch/keylatch:latest ui
```

`KEYLATCH_UI_LISTEN` refuses to bind a non-loopback address automatically
when an LLM session is detected inside the container.

**What works in-container:** the `file` backend, and cloud backends reachable
over plain HTTPS (`aws-sm`, `vault`). **What does not work:** any CLI-driven
backend the distroless image does not ship a binary for — `op`, `bw`,
`keychain`, `lastpass`, `keeper`, `proton-pass`. Use a native install for
those.

## Verify the installation

```bash
keylatch version
```

(`keylatch --version` prints the identical string.)

Expected output (version will vary):

```
keylatch 0.1.0 (abc1234) built 2025-01-01T00:00:00Z
```

## Next step

Run the setup wizard:

```bash
keylatch bootstrap
```

Then open the browser UI to connect your first credential provider:

```bash
keylatch ui
```
