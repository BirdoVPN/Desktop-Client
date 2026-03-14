use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Embed Windows manifest to request admin privileges
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("app.manifest");
        if let Err(e) = res.compile() {
            println!("cargo:warning=Failed to compile Windows resource: {}", e);
        }
    }
    
    tauri_build::build();
    
    // Copy wintun.dll to output directory
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
