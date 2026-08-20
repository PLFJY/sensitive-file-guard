use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GUARDD_BUILD_ID");
    let build_id = env::var("GUARDD_BUILD_ID").unwrap_or_else(|_| {
        let commit = Command::new("git")
            .args(["rev-parse", "--verify", "HEAD"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".to_owned());
        let dirty = Command::new("git")
            .args(["diff", "--quiet", "--", "."])
            .status()
            .map(|status| !status.success())
            .unwrap_or(false);
        if dirty {
            format!("{commit}-dirty")
        } else {
            commit
        }
    });
    println!("cargo:rustc-env=GUARDD_BUILD_ID={build_id}");

    // Keep the LPS3 BPF source beside the daemon so the product, rather than
    // an ad-hoc test script, owns the policy it will attach. Rust integration
    // consumes the resulting object through libbpf at runtime.
    println!("cargo:rerun-if-changed=src/process_shield.bpf.c");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let object = out.join("guardd-process-shield.bpf.o");
    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-c",
            "src/process_shield.bpf.c",
            "-o",
        ])
        .arg(&object)
        .status()
        .expect("clang is required to build guardd's Linux Process Shield BPF object");
    assert!(status.success(), "guardd Process Shield BPF compilation failed");
}
