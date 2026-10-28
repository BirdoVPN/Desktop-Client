# BirdoVPN — Desktop Client

Cross-platform desktop VPN client for [Birdo.app](https://birdo.app), built with
[Tauri](https://tauri.app) — a TypeScript/React frontend wrapped in a Rust core.

- **Product:** `BirdoVPN`  •  **Bundle ID:** `uk.birdo.vpn.desktop`  •  **Targets:** Windows (NSIS), macOS (DMG/app — **unsigned and un-notarised**, see below), Linux (.deb)
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

## Install
Download from the [latest release](https://github.com/BirdoVPN/Desktop-Client/releases/latest)
([verify the download](docs/VERIFICATION.md) first):

- **Windows:** `BirdoVPN_<version>_Windows_x64-setup.exe`. It updates itself in the app.
- **macOS:** `BirdoVPN_<version>_macOS_aarch64.dmg` (Apple silicon) or `..._macOS_x64.dmg` (Intel).
- **Linux (Debian, Ubuntu and derivatives, x86_64):** the `.deb` only.
  ```bash
  sudo apt install ./BirdoVPN_<version>_Linux_amd64.deb
  ```
  Upgrade by installing the next release's `.deb` the same way. The tunnel needs
  root: start BirdoVPN as root, for example `sudo -E birdo-vpn-desktop`.

**No AppImage any more.** Owner decision 2026-10-28: the AppImage carried its own
copies of about 100 Ubuntu libraries, with the licence duties that brings, so Linux
ships as a `.deb` only. 1.4.50 was the last AppImage, and the in-app updater does not
move an AppImage to the `.deb`. To switch: quit the AppImage, install the `.deb` as
above, then delete the AppImage file. The `.deb` is the same app (same identifier and
folders), so settings and sign-in normally carry over when you start it the same way
you started the AppImage; if not, sign in again. To remove the AppImage's data
instead, see [`docs/UNINSTALL.md`](docs/UNINSTALL.md#linux-an-appimage-from-1450-or-earlier).
Other distributions (Fedora, Arch, ...) have no package for now.

## Uninstall
Removing the app keeps its data (keys, tokens, logs, crash reports) unless you
ask for it to go: the Windows uninstaller's **Delete the application data**
box, `apt purge` for the .deb, and on macOS (and an AppImage from 1.4.50 or
earlier) the app's own cleanup flag. See [`docs/UNINSTALL.md`](docs/UNINSTALL.md).

## Release
Pushing a `v*` tag triggers the unified Windows/macOS/Linux release build that is
published as the **Latest** auto-update release. See [`docs/CODE_SIGNING.md`](docs/CODE_SIGNING.md),
[`docs/azure-trusted-signing-setup.md`](docs/azure-trusted-signing-setup.md) and
[`docs/RELEASE-SECRETS.md`](docs/RELEASE-SECRETS.md). Signing secrets live in the operator
vault, never in the repo.

What is signed, today: Windows tag builds are Authenticode-signed (Azure Trusted
Signing) and every release's artefacts are listed in one `SHA256SUMS.txt` that carries a
Sigstore (cosign keyless) signature ([verify a download](docs/VERIFICATION.md)).
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
