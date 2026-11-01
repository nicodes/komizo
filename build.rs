fn main() {
    println!("cargo:rustc-check-cfg=cfg(packed_api)");
    println!("cargo:rerun-if-env-changed=KOMIZO_API_PAYLOAD");
    println!("cargo:rerun-if-env-changed=KOMIZO_VERSION");
    if let Ok(path) = std::env::var("KOMIZO_API_PAYLOAD") {
        assert!(
            std::path::Path::new(&path).is_absolute(),
            "API payload must be absolute"
        );
        println!("cargo:rerun-if-changed={path}");
        println!("cargo:rustc-cfg=packed_api");
    }
}
