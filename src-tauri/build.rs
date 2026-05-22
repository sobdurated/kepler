fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!(
        "cargo:rustc-link-search=native={}/resources/windivert",
        manifest_dir
    );

    println!("cargo:rerun-if-changed=resources/windivert/WinDivert.lib");
    println!("cargo:rerun-if-changed=app.manifest");

    #[cfg(target_os = "windows")]
    {
        let mut windows = tauri_build::WindowsAttributes::new();
        windows = windows.app_manifest(include_str!("app.manifest"));
        tauri_build::try_build(
            tauri_build::Attributes::new().windows_attributes(windows),
        )
        .expect("failed to run build script");
    }
    #[cfg(not(target_os = "windows"))]
    {
        tauri_build::build()
    }
}
