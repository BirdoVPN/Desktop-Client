use std::env;

fn main() {
    // Embed the Windows application manifest (requireAdministrator + OS
    // compatibility) through Tauri's own build mechanism.
    //
    // IMPORTANT: do NOT also embed a manifest via `winres` (the previous
    // approach). tauri-build already injects its own application manifest, so a
    // second winres-embedded manifest collides at link time and the
    // `requestedExecutionLevel` is silently dropped from the final exe — that
    // was the root cause of "the VPN doesn't run as administrator". Feeding our
    // manifest to tauri-build makes it the single source of truth.
    #[cfg(windows)]
    {
        let win = tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest"));
        let attrs = tauri_build::Attributes::new().windows_attributes(win);
        tauri_build::try_build(attrs).expect("failed to run tauri-build with custom manifest");
    }

    #[cfg(not(windows))]
    tauri_build::build();

    // ── Crash reporting must not ship inert ─────────────────────────
    //
    // `main.rs` reads the DSN with `option_env!`, so an absent one compiles
    // to `""` and `sentry::init` becomes a silent no-op: the build is green,
    // the artifact is signed and shipped, and the crash reporter does not
    // exist. That is how the Android client spent months with a blank DSN
    // (Mobile-Client #357), and a `cargo:warning` in a twelve-minute build
    // is not a control — it is a line of scrollback.
    //
    // THE REBUILD TRIGGER IS LOAD-BEARING. Cargo caches a build script by
    // its declared inputs; without this line the check below would be
    // evaluated once and then never again, so setting the secret for the
    // first time would not re-run it — and CI restores `target/` through
    // Swatinem/rust-cache on every job. (The crate body needs no such
    // declaration: cargo tracks `option_env!` itself. Verified by building
    // the same crate with the variable unset, then set, then changed —
    // each build recompiled and produced the new value.)
    println!("cargo:rerun-if-env-changed=SENTRY_DSN");
    println!("cargo:rerun-if-env-changed=BIRDO_ALLOW_MISSING_SENTRY_DSN");
    let profile = env::var("PROFILE").unwrap_or_default();
    if profile == "release" {
        let dsn = env::var("SENTRY_DSN").unwrap_or_default();
        let dsn = dsn.trim();
        let opted_out = !env::var("BIRDO_ALLOW_MISSING_SENTRY_DSN")
            .unwrap_or_default()
            .is_empty();
        if dsn.is_empty() {
            if opted_out {
                println!(
                    "cargo:warning=BUILDING A RELEASE WITH NO CRASH REPORTING. This artifact \
                     cannot report a crash. Never ship it."
                );
            } else {
                panic!(
                    "SENTRY_DSN is not set — refusing to build a release artifact that \
                     cannot report crashes.\n  \
                     CI: the secret is passed at job level by the build jobs in \
                     .github/workflows/; check `gh secret list`.\n  \
                     Local: SENTRY_DSN=https://...@o....ingest.de.sentry.io/... cargo build \
                     --release\n  \
                     Deliberately without: BIRDO_ALLOW_MISSING_SENTRY_DSN=1\n  \
                     See docs/SENTRY-SETUP.md."
                );
            }
        } else if !dsn.starts_with("https://") || !dsn.contains('@') {
            panic!(
                "SENTRY_DSN does not look like a DSN (expected \
                 https://<key>@<host>/<project-id>). A project slug or an auth token \
                 (sntrys_...) would compile and then silently fail to ingest."
            );
        } else {
            println!("cargo:warning=Sentry: release build has a DSN — crash reporting is ARMED.");
        }
    }

    // Linux: check for required system libraries
    #[cfg(target_os = "linux")]
    {
        // Ensure pkg-config can find GTK and WebKit (required by Tauri on Linux)
        println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    }

    // Copy wintun.dll to output directory (Windows only)
    #[cfg(windows)]
    {
        use std::fs;
        use std::path::Path;

        let out_dir = env::var("OUT_DIR").unwrap();
        let profile = if out_dir.contains("debug") {
            "debug"
        } else {
            "release"
        };

        let target_dir = Path::new("target").join(profile);
        let wintun_src = Path::new("wintun-extract/wintun/bin/amd64/wintun.dll");
        let wintun_dst = target_dir.join("wintun.dll");

        if wintun_src.exists() && !wintun_dst.exists() {
            if let Err(e) = fs::copy(wintun_src, &wintun_dst) {
                println!("cargo:warning=Failed to copy wintun.dll: {}", e);
            } else {
                println!("cargo:warning=Copied wintun.dll to {:?}", wintun_dst);
            }
        }
    }
}
