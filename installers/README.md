# Installers

Installation methods for Keylatch.

## Homebrew (macOS / Linux)

```bash
brew tap keylatch/tap
brew install keylatch
```

The tap repository is at `https://github.com/keylatch/homebrew-tap`. The formula is generated from `homebrew/keylatch.rb.tmpl` during the release pipeline.

## Scoop (Windows)

```powershell
scoop bucket add keylatch https://github.com/keylatch/scoop-bucket
scoop install keylatch
```

The Scoop manifest is generated from `scoop/keylatch.json.tmpl` during the release pipeline.

## Docker

```bash
docker pull ghcr.io/keylatch/keylatch:latest
```

The image is published to the GitHub Container Registry on each tagged release.

## deb / rpm

Native `.deb` and `.rpm` packages are planned for post-v1.0. Track progress in the issue tracker.
