use std::path::Path;

fn main() {
    println!("cargo:rerun-if-env-changed=WIMLIB_DIR");

    if let Ok(dir) = std::env::var("WIMLIB_DIR") {
        let lib_dir = Path::new(&dir).join("lib");
        if lib_dir.exists() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
        }
    } else {
        for prefix in ["/opt/homebrew/opt/wimlib", "/usr/local/opt/wimlib"] {
            let lib_dir = Path::new(prefix).join("lib");
            if lib_dir.exists() {
                println!("cargo:rustc-link-search=native={}", lib_dir.display());
                break;
            }
        }
    }

    println!("cargo:rustc-link-lib=wim");
}
