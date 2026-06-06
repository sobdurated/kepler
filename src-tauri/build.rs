fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!(
        "cargo:rustc-link-search=native={}/resources/windivert",
        manifest_dir
    );

    println!("cargo:rerun-if-changed=resources/windivert/WinDivert.lib");
    println!("cargo:rerun-if-changed=app.manifest");

    let mut attributes = tauri_build::Attributes::new();

    #[cfg(target_os = "windows")]
    {
        let mut windows = tauri_build::WindowsAttributes::new();
        windows = windows.app_manifest(include_str!("app.manifest"));
        attributes = attributes.windows_attributes(windows);
    }

    tauri_build::try_build(attributes).expect("failed to run build script");
}
