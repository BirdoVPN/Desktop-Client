use std::env;

fn main() {
    // Embed Windows manifest to request admin privileges
    #[cfg(windows)]
    {
        let winres = winres::WindowsResource::new();
        let mut res = winres;
        res.set_manifest_file("app.manifest");
        if let Err(e) = res.compile() {
            println!("cargo:warning=Failed to compile Windows resource: {}", e);
        }
    }
    
    tauri_build::build();

    // Warn if SENTRY_DSN is missing on release builds
    let profile = env::var("PROFILE").unwrap_or_default();
    if profile == "release" {
        if env::var("SENTRY_DSN").unwrap_or_default().is_empty() {
            println!("cargo:warning=SENTRY_DSN is not set — crash reporting will be disabled in this release build");
        }
    }
    
    // Copy wintun.dll to output directory (Windows only)
    #[cfg(windows)]
    {
        use std::fs;
        use std::path::Path;
        
        let out_dir = env::var("OUT_DIR").unwrap();
        let profile = if out_dir.contains("debug") { "debug" } else { "release" };
        
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
