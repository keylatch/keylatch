## Release checklist - {{VERSION}}

- [ ] macOS notarisation: check `desktop-bundles (macos-14)` step `notarize` outcome in the release workflow
- [ ] Windows EV signing: check `desktop-bundles (windows-latest)` step `win_sign` outcome
- [ ] Homebrew formula updated - `brew tap keylatch/tap && brew install keylatch && keylatch --version`
- [ ] Scoop manifest updated - `scoop install keylatch && keylatch --version`
- [ ] cosign signatures verified on all CLI artifacts - `keylatch verify --self`
- [ ] SBOM attached to release (`.cdx.json` + `.spdx.json` present on GitHub Release)
- [ ] Release notes published at keylatch.dev/release-notes/{{VERSION}}
