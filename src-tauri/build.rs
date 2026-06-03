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

    // Warn if SENTRY_DSN is missing on release builds
    let profile = env::var("PROFILE").unwrap_or_default();
    if profile == "release" {
        if env::var("SENTRY_DSN").unwrap_or_default().is_empty() {
            println!("cargo:warning=SENTRY_DSN is not set — crash reporting will be disabled in this release build");
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
