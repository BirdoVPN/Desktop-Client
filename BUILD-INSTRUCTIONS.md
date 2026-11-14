# Rebuilding Birdo VPN Desktop

This page tells a third party how to rebuild the Desktop client from a release tag
and compare the result with what we ship. Every pin below is copied from a file in
this repository (the source is named next to it), so the files win if this page
ever drifts. Nothing here needs a secret.

For checking a download against our published checksums, see
[`docs/VERIFICATION.md`](docs/VERIFICATION.md). This page is about the other
direction: building it yourself.

## What "reproducible" means here, honestly

We do **not** claim bit-for-bit reproducible installers today. What you can do:

- Rebuild every payload with the exact toolchain and inputs CI uses (pinned below).
- Compare the **unsigned** build outputs, and the pieces that are deterministic
  (the Rust binary, the vendored Xray binary), with ours.
- Check the Xray engine against the hash this repository pins.

What you cannot expect to match byte for byte, and why, is in
[Known non-determinism](#known-non-determinism). Please read it before you
report a mismatch as a bug.

## Pinned inputs

| Input | Pin | Source of truth |
|---|---|---|
| Rust | `1.96.0`, components `rustfmt` + `clippy`, profile `minimal` | `rust-toolchain.toml` |
| Cargo dependencies | exactly `src-tauri/Cargo.lock`, built with `--locked` | `src-tauri/Cargo.lock`, `release.yml` (`tauri build -- --locked`) |
| Release profile | `panic=abort`, `codegen-units=1`, `lto=true`, `opt-level="s"`, `strip=true` | `src-tauri/Cargo.toml` `[profile.release]` |
| Node.js | `22` (no `.nvmrc`, no `engines` field: the workflows are the pin) | `actions/setup-node` in `.github/workflows/release.yml` |
| npm packages | exactly `package-lock.json` via `npm ci` (Tauri CLI `@tauri-apps/cli` 2.12.4 at the time of writing) | `package-lock.json` |
| Xray-core (Reality engine) | `v26.3.27`, source commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`, tree `dbcb1d31713edfcf5860cf35feee0632e9117893` | `XRAY_*` in `release.yml` `env:` |
| Xray zip, Windows x64 | SHA-256 `d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad` | `XRAY_WINDOWS_SHA256` |
| Xray zip, Linux x64 | SHA-256 `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae` | `XRAY_LINUX_SHA256` |
| Xray zip, macOS arm64 | SHA-256 `2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf` | `XRAY_MACOS_ARM64_SHA256` |
| Xray zip, macOS x64 | SHA-256 `f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203` | `XRAY_MACOS_AMD64_SHA256` |
| Wintun (Windows) | `wintun-0.14.1.zip`, SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` | "Download Wintun" step in `release.yml` |
| CI runners | Windows `windows-2025`, Linux `ubuntu-22.04`, macOS `macos-15` | `runs-on` / `matrix.runner` in `release.yml` |
| Linux system packages | `libwebkit2gtk-4.1-dev librsvg2-dev patchelf libgtk-3-dev libayatana-appindicator3-dev` (unversioned: whatever the runner's Ubuntu 22.04 archive has that day) | `.github/actions/linux-deps/action.yml` |
| Third-party GitHub Actions | each pinned by commit SHA | `uses:` lines in the workflows |

Not pinned (see gaps): the Linux system packages, the macOS/Windows runner image
contents (Xcode, MSVC, Windows SDK), the NSIS and WiX tools that the Tauri
bundler downloads, and Docker images (CI builds Desktop on bare runners, not in
containers, so there is no image digest to give).

The Xray version bump procedure and the Go modules inside the Xray binaries are
described by `scripts/build-corresponding-source.mjs`, which builds the
`BirdoVPN-<version>-corresponding-source.tar.gz` asset each release carries.

## Prerequisites

- The repository at a release tag `vX.Y.Z` (releases are built only from tags on `main`).
- Rust via [rustup](https://rustup.rs): inside the checkout, `rustup toolchain install`
  reads `rust-toolchain.toml` and installs exactly 1.96.0 (this is what
  `.github/actions/setup-rust` does).
- Node.js 22 and npm.
- Per platform, the Tauri 2 system prerequisites: MSVC build tools and the Windows SDK
  (Windows), Xcode command line tools (macOS), the GTK/WebKit packages above (Linux).

## Common steps

```bash
git clone https://github.com/BirdoVPN/Desktop-Client.git && cd Desktop-Client
git checkout vX.Y.Z
rustup toolchain install          # reads rust-toolchain.toml -> 1.96.0
npm ci
mkdir -p src-tauri/resources && rm -f src-tauri/resources/.gitkeep
```

### Fetch and verify the Xray engine

Download the asset for your platform from
`https://github.com/XTLS/Xray-core/releases/download/v26.3.27/` (`Xray-windows-64.zip`,
`Xray-linux-64.zip`, `Xray-macos-arm64-v8a.zip` or `Xray-macos-64.zip`), verify the zip
against the SHA-256 in the table, extract the executable into
`src-tauri/resources/` as `xray.exe` (Windows) or `xray` (Linux, macOS), then compute its
SHA-256 and export it as `XRAY_BINARY_SHA256`. The app compiles that value in and
refuses to run an Xray that does not hash to it.

```bash
sha256sum src-tauri/resources/xray            # macOS: shasum -a 256
export XRAY_BINARY_SHA256=<that value>
```

On Windows also place `wintun.dll` (from the amd64 folder of the verified Wintun zip) at
`src-tauri/resources/wintun.dll` and `src-tauri/wintun-extract/wintun/bin/amd64/wintun.dll`,
as the release job does.

### Generate the notices, then build

```bash
# Linux and macOS (Windows adds --wintun-license, see release.yml). <target> is the
# Rust target triple you build for, <xray-zip-dir>/LICENSE is the LICENSE from the
# Xray zip you extracted.
node scripts/generate-third-party-notices.mjs --release --target <target>   --xray src-tauri/resources/xray --xray-license <xray-zip-dir>/LICENSE
export SENTRY_DSN=https://example.invalid/0          # see below
export TAURI_SIGNING_PRIVATE_KEY=...                  # see below, or omit updater artifacts
npx tauri build -- --locked
```

Two build inputs are secrets in our CI and will not match yours:

- `SENTRY_DSN`. `src-tauri/build.rs` refuses a release build without one. For a
  rebuild, set `BIRDO_ALLOW_MISSING_SENTRY_DSN=1` instead (the unsigned PR workflows
  `nsis-installer.yml` and `linux-packages.yml` do exactly this). The DSN is compiled
  into the binary, so **your binary differs from ours at that string, by design.**
- `BIRDO_DESKTOP_ATTEST_SK` / `BIRDO_DESKTOP_ATTEST_KID`, the client-attestation key
  (`docs/CLIENT-ATTESTATION.md`). It is read with `option_env!`; leave it unset and the
  build works but your client will not pass server attestation. Also compiled in, so a
  further expected difference.
- `TAURI_SIGNING_PRIVATE_KEY` signs the updater `.sig` files. `linux-packages.yml`
  shows the throwaway-key approach (`tauri signer generate`).

## Per-artefact commands

The commands are exactly what `release.yml` runs, minus signing.

| Artefact | Runner | Command |
|---|---|---|
| Windows NSIS installer `*-setup.exe` | `windows-2025` | `npx tauri build -- --locked` (bundle target `nsis`; `bundle.targets` in `src-tauri/tauri.conf.json` is `["nsis","dmg","app","deb"]`, `wix` is `null`, so no MSI) |
| Linux `.deb` (amd64) | `ubuntu-22.04` | `npx tauri build --target x86_64-unknown-linux-gnu -- --locked`. Linux ships the `.deb` only; the AppImage was dropped (owner decision 2026-10-28) |
| macOS `.dmg` + `.app.tar.gz` (arm64) | `macos-15` | generate `src-tauri/icons/icon.icns` from `icon.png` with `sips`/`iconutil` as in `release.yml`, then `npx tauri build --target aarch64-apple-darwin -- --locked` |
| macOS `.dmg` + `.app.tar.gz` (x64) | `macos-15` | same, `--target x86_64-apple-darwin` (needs `rustup target add x86_64-apple-darwin`) |

The macOS DMG is retired once the Mac App Store app is live; the App Store build is made
by the **Mobile-Client** repository (`macos.yml`, see its `BUILD-INSTRUCTIONS.md`).

Outputs land in `src-tauri/target/[<target>/]release/bundle/`.

## What is signed, and what to compare

| Platform | What we add after the build | What you compare |
|---|---|---|
| Windows | Authenticode via Azure Trusted Signing. `release.yml` signs `xray.exe` **before** bundling and recomputes `XRAY_BINARY_SHA256` from the signed bytes; the bundler then signs the installer and the binaries in it. | Build unsigned (no `signCommand`). Compare the unsigned `birdo-vpn-desktop.exe` and the unsigned `xray.exe` hash. Our shipped `xray.exe` is the Xray release binary **plus a signature**, so its hash differs from the zip's on purpose: remove the signature (for example with `osslsigncode remove-signature`) and compare with the hash of `xray.exe` inside the verified zip. |
| macOS | Developer ID codesign and Apple notarisation plus a stapled ticket, when Apple secrets exist. | Compare the unsigned binary inside `BirdoVPN.app/Contents/MacOS/` after `codesign --remove-signature`, and the bundled `xray`. |
| Linux | Nothing is added to the `.deb`. | Compare the `.deb` payload: `dpkg-deb -x` both and `diff -r`, or run `diffoscope`. |
| All | `SHA256SUMS.txt` plus `SHA256SUMS.txt.sigstore` over every released file. Updater `.sig` files from the Tauri key. | Use `docs/VERIFICATION.md` for these. |

CI records two build-time hash gates you can read and rerun:

- `scripts/ci/verify-bundled-xray.sh` (Linux, macOS) and
  `scripts/ci/verify-bundled-xray-hash.ps1` (Windows): the xray inside the finished
  installer or package must hash to the `XRAY_BINARY_SHA256` compiled into the app.
- `scripts/ci/verify-release-updater-signatures.sh`: the updater `.sig` files verify.

## Expected outputs

Each release publishes `SHA256SUMS.txt` (SHA-256 of every installer, package and the
corresponding-source archive), signed with Sigstore. Those are the hashes of the
**signed** artefacts, so they are the right thing to check a download against, but not
a target an unsigned rebuild will hit. Per-artefact hashes of the unsigned payloads
are **not yet published**. That is the gap that blocks a true bit-for-bit comparison.

## Known non-determinism

- **Signatures and timestamps.** Authenticode and Apple signatures embed a signer
  certificate and an RFC 3161 timestamp. Azure Trusted Signing mints a fresh short-lived
  certificate per run, so two signings of identical bytes never match.
- **Compiled-in secrets.** `SENTRY_DSN` and the attestation key (see above).
- **Embedded paths.** Rust embeds source paths (panic locations, debug-info remnants,
  the registry path of dependencies) and `strip = true` removes symbols but not all
  paths. Building from a different directory or with a different `CARGO_HOME` can change
  the binary. In our one test a copy of the tree in a different directory produced an identical
  binary (below), so paths did not leak into the executable there; that was one OS and
  not a bundle. `--remap-path-prefix` can be passed
  through `RUSTFLAGS` to neutralise it, and CI does not set it today.
- **Tauri bundling.** The bundler builds NSIS/DMG/deb containers; file modification
  times, compression and (for NSIS) the downloaded NSIS toolchain can all vary. Since
  Tauri 2.10 the bundler also patches and signs a copy of the binary per bundle.
  Compare payloads, not containers.
- **macOS.** `sips` and `iconutil` generate `icon.icns`; the DMG is built with `hdiutil`
  (timestamps, volume UUID); notarisation staples a ticket. There is no Apple bitcode
  in this build (bitcode is gone since Xcode 14).
- **Runner image drift.** MSVC, Windows SDK, Xcode, the Linux libraries and the
  linker are those of the day's hosted runner image. We do not pin them.
- **Xray.** The engine is **vendored** as an upstream release binary, not compiled by us.
  It reproduces as far as XTLS's own release does. Its hash is pinned and checked, and
  the corresponding-source asset names the Go toolchain and every Go module it links.

## Verification of this page

The Rust crate (`src-tauri`) was built six times with the pinned toolchain on a macOS
arm64 machine; see the result below.

### Verification result

Rust crate built on macOS 26.5.2 (arm64, Apple M3, Xcode 26.6 command line tools) with rustc 1.96.0
(`RUSTUP_TOOLCHAIN=1.96.0`), `cargo build --locked --release --bins --features tauri/custom-protocol`
in `src-tauri` (the CLI's own cargo invocation, host target `aarch64-apple-darwin`, a stub `dist/`,
`BIRDO_ALLOW_MISSING_SENTRY_DSN=1`), `target/` removed before each build. The binary is the Tauri
executable alone, not a bundle.

| Build | Directory | SHA-256 of `birdo-vpn-desktop` (9,616,272 bytes) |
|---|---|---|
| 1 (first ever, cold cargo registry) | A | `1f7bd5e556c745540e5036aa0e6a3988826ebd3180d52b43e991b91abd0e0a69` |
| 2 | A | `385830188abd8ef50d21cd069a1b29d6824e49d4c7ec17575aeedb2114f38498` |
| 3 | A | `385830188abd8ef50d21cd069a1b29d6824e49d4c7ec17575aeedb2114f38498` |
| 4 (second session) | A | `385830188abd8ef50d21cd069a1b29d6824e49d4c7ec17575aeedb2114f38498` |
| 5 (second session) | A | `385830188abd8ef50d21cd069a1b29d6824e49d4c7ec17575aeedb2114f38498` |
| 6 (second session) | B (a different path, copied tree) | `385830188abd8ef50d21cd069a1b29d6824e49d4c7ec17575aeedb2114f38498` |

Builds 2 to 6 are bit-identical (`cmp` finds 0 differing bytes between builds, including across
two directories). The very first build, on a machine that had not built this crate before, produced
a different binary of the same size. We did not find the cause (a guess is a cold-start input such as
the fresh registry download, but that is unproven). Treat a first, cold build as a possible source of a
mismatch and build twice. This was one machine and one OS; it says nothing about Windows or Linux.

## Gaps we know about

- No published hash for unsigned payloads (proposal in the pull request: add them to
  the release's checksum file).
- No `SOURCE_DATE_EPOCH` or `--remap-path-prefix` in CI.
- Linux system libraries and runner images are not pinned; no container images are used.
- NSIS and the Tauri bundler's downloaded tools are not pinned by hash in this repository.
- `release.yml` is the authoritative build recipe; where this page and it differ, follow it.
