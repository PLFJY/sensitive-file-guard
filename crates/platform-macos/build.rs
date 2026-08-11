fn main() {
    println!("cargo:rerun-if-changed=../../native/macos/system_extension_bridge.m");
    println!("cargo:rerun-if-changed=../../native/macos/system_extension_bridge.h");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }

    cc::Build::new()
        .file("../../native/macos/system_extension_bridge.m")
        .flag("-fobjc-arc")
        .flag("-fblocks")
        .flag("-fmodules")
        .flag("-Wall")
        .flag("-Wextra")
        .warnings_into_errors(true)
        .compile("guard_macos_bridge");
    println!("cargo:rustc-link-lib=framework=Foundation");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=SystemExtensions");
}
