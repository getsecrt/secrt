use std::path::Path;

fn main() {
    // Ensure web/dist exists so rust-embed doesn't fail at compile time during dev builds
    let dist = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/dist");
    if !dist.exists() {
        std::fs::create_dir_all(&dist).expect("failed to create web/dist");
    }
    println!("cargo::rerun-if-changed=../../web/dist");
}
