# Tauri Icon Placeholders

The files in this directory are **placeholder icons** generated with a solid Keylatch brand color (`#1e40af` dark blue). They satisfy the `cargo tauri build` icon resolver so the CI release workflow does not fail, but they are not suitable for the final 0.1.0 tag.

## Before tagging v0.1.0

1. Obtain or design a proper 1024x1024 source PNG (`icon-source-1024.png`).
2. Run from `src-tauri/`:

   ```bash
   cargo tauri icon ../path/to/icon-source-1024.png
   ```

   This regenerates all icon variants at correct dimensions and replaces these placeholders.

3. Commit the new icons and remove this README note about placeholders.

## Files

| File | Dimensions | Format | Notes |
|------|-----------|--------|-------|
| `32x32.png` | 32x32 | PNG RGB | Tauri bundle (Windows taskbar, Linux) |
| `128x128.png` | 128x128 | PNG RGB | Tauri bundle |
| `128x128@2x.png` | 256x256 | PNG RGB | Tauri bundle (HiDPI) |
| `icon.png` | 512x512 | PNG RGB | Tray icon + Tauri bundle |
| `icon.ico` | 32x32 | ICO 24-bpp | Windows bundle |
| `icon.icns` | 32x32 | ICNS (icp4) | macOS bundle (placeholder only — replace with full ICNS set) |
