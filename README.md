# BirdoVPN — Desktop Client

Cross-platform desktop VPN client for [Birdo.app](https://birdo.app), built with
[Tauri](https://tauri.app) — a TypeScript/React frontend wrapped in a Rust core.

- **Product:** `BirdoVPN`  •  **Bundle ID:** `uk.birdo.vpn.desktop`  •  **Targets:** Windows (NSIS/MSI), macOS (DMG/app), Linux (deb/AppImage)
- **Version** is the single source of truth in `src-tauri/tauri.conf.json` **and** `package.json` — they **must match** (CI enforces this; a mismatch fails the release build).

## Layout
```
src/          TypeScript/React UI (Vite)
src-tauri/    Rust core — WireGuard tunnel, cert-pinning, IPC commands
  tauri.conf.json   app identity, bundle targets, updater config
docs/         signing, release, verification, store-listing guides
scripts/      build/release helpers
```

## Develop
```bash
npm install
npm run tauri:dev      # run the app with hot-reload
npm run type-check     # tsc --noEmit
npm run lint           # eslint (max-warnings 0)
npm run test:run       # vitest
```

## Build
```bash
npm run tauri:build    # produces installers under src-tauri/target/release/bundle/
```

## Release
Pushing a `win-v*` tag triggers a signed Windows build that is published as the **Latest**
auto-update release. See [`docs/CODE_SIGNING.md`](docs/CODE_SIGNING.md),
[`docs/windows-code-signing.md`](docs/windows-code-signing.md) and
[`docs/RELEASE-SECRETS.md`](docs/RELEASE-SECRETS.md). Signing secrets live in the operator
vault, never in the repo.

## Related
- `../birdo-shared/` — shared `protocol.json` + `cert-pins.json` contract (cert pins are mirrored here for DER verification).
- `../birdo-web/` — backend that serves the auth/session/VPN APIs and the Tauri update manifest.
