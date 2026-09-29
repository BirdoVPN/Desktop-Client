# BirdoVPN — Desktop Client

Cross-platform desktop VPN client for [Birdo.app](https://birdo.app), built with
[Tauri](https://tauri.app) — a TypeScript/React frontend wrapped in a Rust core.

- **Product:** `BirdoVPN`  •  **Bundle ID:** `uk.birdo.vpn.desktop`  •  **Targets:** Windows (NSIS), macOS (DMG/app — **unsigned and un-notarised**, see below), Linux (deb/AppImage)
- **Licence:** source-available under CC BY-NC 4.0 (see `LICENSE`) — not an OSI open-source licence. © Birdo Networks Ltd.
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
Pushing a `v*` tag triggers the unified Windows/macOS/Linux release build that is
published as the **Latest** auto-update release. See [`docs/CODE_SIGNING.md`](docs/CODE_SIGNING.md),
[`docs/azure-trusted-signing-setup.md`](docs/azure-trusted-signing-setup.md) and
[`docs/RELEASE-SECRETS.md`](docs/RELEASE-SECRETS.md). Signing secrets live in the operator
vault, never in the repo.

What is signed, today: Windows tag builds are Authenticode-signed (Azure Trusted
Signing) and every platform's artefacts carry a Sigstore (cosign keyless) bundle.
The **macOS** Tauri build is **not** Developer-ID signed or notarised — there is no
Apple Developer account, so `release.yml` always builds it unsigned. No release
artefact is PGP-signed.

Crash reporting is **opt-in**: nothing is sent to Sentry unless the user turns it
on (consent screen or Settings › Privacy); it is off by default, including for
installs upgraded from builds that reported unconditionally. When on, it sends
crash and error reports: crashes, and errors when an app feature such as
connecting fails (today the secure-DNS certificate-pin failures), with the app and
OS version and device model. The DSN is still
compiled in at build time from the `SENTRY_DSN` secret, and a release build with no
usable DSN fails rather than shipping an opt-in that cannot work — see
[`docs/SENTRY-SETUP.md`](docs/SENTRY-SETUP.md) for the project setup, the
verification steps and exactly what a crash report may contain.

## Related
- `../birdo-shared/` — shared `protocol.json` + `cert-pins.json` contract (CA-chain SPKI pins are mirrored here in `third_party/cert-pins.json`).
- `../birdo-web/` — backend that serves the auth/session/VPN APIs and the Tauri update manifest.
