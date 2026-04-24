fn main() {
    println!("cargo:rerun-if-env-changed=WIMLIB_DIR");

    if let Ok(dir) = std::env::var("WIMLIB_DIR") {
        println!("cargo:rustc-link-search=native={}", dir);
    } else {
        // Common homebrew/local paths for macOS
        for prefix in ["/opt/homebrew/opt/wimlib", "/usr/local/opt/wimlib"] {
            let path = std::path::Path::new(prefix).join("lib");
            if path.exists() {
                println!("cargo:rustc-link-search=native={}", path.display());
                break;
            }
        }
    }

    println!("cargo:rustc-link-lib=wim");
}
