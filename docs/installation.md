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
scoop bucket add keylatch https://github.com/keylatch/scoop-bucket
scoop install keylatch
```

## Linux — Manual tarball

Download the latest release tarball from [GitHub Releases](https://github.com/keylatch/keylatch/releases):

```bash
# Replace X.Y.Z with the latest version.
curl -Lo keylatch.tar.gz \
  https://github.com/keylatch/keylatch/releases/latest/download/keylatch_linux_amd64.tar.gz

tar -xzf keylatch.tar.gz
sudo mv keylatch /usr/local/bin/keylatch
sudo chmod +x /usr/local/bin/keylatch
```

Verify the checksum against the `.sha256` file published alongside each release.

## Docker

The `keylatchd` sidecar is available as a minimal image:

```bash
docker pull ghcr.io/keylatch/keylatch:latest
```

Run as a sidecar bound to loopback only:

```bash
docker run --rm -p 127.0.0.1:7890:7890 \
  -v "$HOME/.keylatch:/root/.keylatch" \
  ghcr.io/keylatch/keylatch:latest
```

## Verify the installation

```bash
keylatch version
```

Expected output (version will vary):

```
keylatch 0.1.0 (commit abc1234, built 2025-01-01T00:00:00Z)
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
