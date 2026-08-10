use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/ssh_behavior.bpf.c");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let object = out.join("ssh_behavior.bpf.o");
    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-D__TARGET_ARCH_x86",
            "-I/usr/include",
            "-c",
            "bpf/ssh_behavior.bpf.c",
            "-o",
        ])
        .arg(&object)
        .status()
        .expect("clang is required to compile the SSH BPF program");
    assert!(status.success(), "clang failed compiling SSH BPF program");
}
