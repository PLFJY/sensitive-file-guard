//! `guard-test-probe` — transparent local access probes for defensive tests.
//!
//! The binary only accesses paths supplied on its command line. Its only IPC
//! transport is a local Unix-domain socket used by the synthetic-canary test
//! sink; it contains no IP networking, persistence, or background execution.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

const CANARY_PREFIX: &[u8] = b"SDF_CANARY_";
const MAX_CANARY_LEN: usize = 256;

/// Process Shield synthetic-target canary length (MPS9). The canary is a
/// random in-memory buffer that must never be recoverable by an untrusted
/// probe.
const SHIELD_CANARY_LEN: usize = 64;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("shield-target") if (3..=5).contains(&args.len()) => {
            let seconds = args.get(3).and_then(|value| value.parse::<u64>().ok());
            let protected = args.get(4).map(PathBuf::from);
            do_shield_target(Path::new(&args[2]), seconds, protected.as_deref())
        }
        Some("shield-authority") if (6..=7).contains(&args.len()) && args[4] == "--profile" => {
            let seconds = args.get(6).and_then(|value| value.parse::<u64>().ok());
            do_shield_authority(Path::new(&args[2]), Path::new(&args[3]), seconds)
        }
        Some("probe-task") if args.len() == 4 => {
            let pid = match args[2].parse::<i32>() {
                Ok(pid) => pid,
                Err(_) => {
                    eprintln!("guard-test-probe: TARGET_PID must be an integer");
                    return ExitCode::from(2);
                }
            };
            do_probe_task(pid, &args[3])
        }
        Some("probe-memory") if args.len() == 3 => {
            let pid = match args[2].parse::<i32>() {
                Ok(pid) => pid,
                Err(_) => {
                    eprintln!("guard-test-probe: TARGET_PID must be an integer");
                    return ExitCode::from(2);
                }
            };
            do_probe_memory(pid)
        }
        Some("shield-target") if (3..=5).contains(&args.len()) => {
            let seconds = args.get(3).and_then(|value| value.parse::<u64>().ok());
            let protected = args.get(4).map(PathBuf::from);
            do_shield_target(Path::new(&args[2]), seconds, protected.as_deref())
        }
        Some("probe-task") if args.len() == 4 => {
            let pid = match args[2].parse::<i32>() {
                Ok(pid) => pid,
                Err(_) => {
                    eprintln!("guard-test-probe: TARGET_PID must be an integer");
                    return ExitCode::from(2);
                }
            };
            do_probe_task(pid, &args[3])
        }
        Some("probe-memory") if args.len() == 3 => {
            let pid = match args[2].parse::<i32>() {
                Ok(pid) => pid,
                Err(_) => {
                    eprintln!("guard-test-probe: TARGET_PID must be an integer");
                    return ExitCode::from(2);
                }
            };
            do_probe_memory(pid)
        }
        Some("read") if args.len() == 3 => do_read(Path::new(&args[2])),
        Some("write-file") if args.len() == 4 => {
            do_write_file(Path::new(&args[2]), args[3].as_bytes())
        }
        Some("mmap") if args.len() == 3 => do_mmap(Path::new(&args[2])),
        Some("sqlite") if args.len() == 3 => do_sqlite(Path::new(&args[2])),
        Some("copy-read") if args.len() == 4 => {
            do_copy_read(Path::new(&args[2]), Path::new(&args[3]))
        }
        Some("child-read") if args.len() == 3 => do_child_read(Path::new(&args[2])),
        Some("read-then-child-read") if args.len() == 3 => {
            do_read_then_child_read(Path::new(&args[2]))
        }
        Some("proc-fd") if args.len() == 4 => do_proc_fd(&args[2], &args[3]),
        Some("hold-fd") if args.len() == 4 => do_hold_fd(Path::new(&args[2]), Path::new(&args[3])),
        Some("exfil-unix") if args.len() == 4 => {
            do_exfil_unix(Path::new(&args[2]), Path::new(&args[3]), false)
        }
        Some("sqlite-exfil-unix") if args.len() == 4 => {
            do_exfil_unix(Path::new(&args[2]), Path::new(&args[3]), true)
        }
        Some("topology-race") if args.len() == 5 => {
            let iterations = match args[4].parse::<u64>() {
                Ok(value) if value > 0 => value,
                _ => {
                    eprintln!("guard-test-probe: ITERATIONS must be a positive integer");
                    return ExitCode::from(2);
                }
            };
            do_topology_race(Path::new(&args[2]), Path::new(&args[3]), iterations)
        }
        Some("open-bench") if args.len() == 4 => {
            let iterations = match args[3].parse::<u64>() {
                Ok(value) if value > 0 => value,
                _ => {
                    eprintln!("guard-test-probe: ITERATIONS must be a positive integer");
                    return ExitCode::from(2);
                }
            };
            do_open_bench(Path::new(&args[2]), iterations)
        }
        Some("alias-race") if args.len() == 6 => {
            let iterations = match args[5].parse::<u64>() {
                Ok(value) if value > 0 => value,
                _ => {
                    eprintln!("guard-test-probe: ITERATIONS must be a positive integer");
                    return ExitCode::from(2);
                }
            };
            do_alias_race(
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
                iterations,
            )
        }
        Some("promote-rename") if args.len() == 5 => do_promote_rename(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        ),
        Some("deny-rename-retry") if args.len() == 4 => {
            do_deny_rename_retry(Path::new(&args[2]), Path::new(&args[3]))
        }
        Some("transit-rename") if args.len() == 5 => do_transit_rename(
            Path::new(&args[2]),
            Path::new(&args[3]),
            Path::new(&args[4]),
        ),
        #[cfg(target_os = "linux")]
        Some("rename-out-race") if args.len() == 6 => {
            let iterations = match args[5].parse::<u64>() {
                Ok(value) if value > 0 => value,
                _ => {
                    eprintln!("guard-test-probe: ITERATIONS must be a positive integer");
                    return ExitCode::from(2);
                }
            };
            do_rename_out_race(
                Path::new(&args[2]),
                Path::new(&args[3]),
                Path::new(&args[4]),
                iterations,
            )
        }
        #[cfg(target_os = "linux")]
        Some("fsmark-remove") if args.len() == 4 => do_fsmark(
            args[2].parse::<i32>().ok(),
            None,
            Path::new(&args[3]),
            false,
        ),
        #[cfg(target_os = "linux")]
        Some("fsmark-restore") if args.len() == 5 => {
            // Explicit fd (the remove call printed it); the scan cannot find
            // the group once its marks are gone.
            do_fsmark(
                args[2].parse::<i32>().ok(),
                args[3].parse::<i32>().ok(),
                Path::new(&args[4]),
                true,
            )
        }
        #[cfg(target_os = "linux")]
        Some("fsmark-restore") if args.len() == 4 => {
            do_fsmark(args[2].parse::<i32>().ok(), None, Path::new(&args[3]), true)
        }
        _ => {
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage: guard-test-probe COMMAND ...\n\
         commands:\n\
           read PATH\n\
           write-file PATH CONTENT\n\
           mmap PATH\n\
           sqlite DATABASE\n\
           copy-read SOURCE DESTINATION\n\
           child-read PATH\n\
           read-then-child-read PATH\n\
           proc-fd PID FD\n\
           hold-fd PATH READY_FILE\n\
           exfil-unix PATH SOCKET\n\
           sqlite-exfil-unix DATABASE SOCKET\n\
           topology-race TARGET STAGING_DIR ITERATIONS\n\
           open-bench PATH ITERATIONS\n\
           alias-race TARGET STAGING_DIR EXTERNAL_ALIAS ITERATIONS
           promote-rename STAGED TARGET EXTERNAL
           deny-rename-retry TARGET EXTERNAL
           transit-rename STAGED TARGET EXTERNAL
           rename-out-race TARGET OUTSIDE_DIR TEMP ITERATIONS (linux)
           fsmark-remove PID PATH (linux)
           fsmark-restore PID PATH (linux)
           shield-target READY_FILE [SECONDS] [PROTECTED_FILE]
           shield-authority READY_FILE WEB_STORAGE --profile PROFILE [SECONDS]
           probe-task TARGET_PID control|read
           probe-memory TARGET_PID"
    );
}

/// Linux LPS5 daemon-integrated target. Its command line deliberately carries
/// an exact `--profile` binding, while its first protected WebStorage open is
/// what causes running guardd to admit the exact process instance. The marker
/// is written only after that open returns, so an attacker never races ahead of
/// the File Shield pre-response admission boundary.
fn do_shield_authority(ready_file: &Path, web_storage: &Path, seconds: Option<u64>) -> ExitCode {
    let mut canary = Box::new([0u8; SHIELD_CANARY_LEN]);
    if let Ok(mut random) = File::open("/dev/urandom") {
        let _ = random.read_exact(&mut *canary);
    }
    let hex = canary
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let pid = std::process::id();
    if let Err(error) = std::fs::write(
        ready_file,
        format!("{pid} {hex} 0x{:x}\n", canary.as_ptr() as usize),
    ) {
        eprintln!("guard-test-probe: cannot write shield-authority ready file: {error}");
        return ExitCode::from(2);
    }
    if let Err(error) = std::fs::read(web_storage) {
        eprintln!("guard-test-probe: shield-authority WebStorage open failed: {error}");
        return ExitCode::from(3);
    }
    let admitted = ready_file.with_extension("admitted");
    if let Err(error) = std::fs::write(&admitted, format!("{pid}\n")) {
        eprintln!("guard-test-probe: cannot write shield-authority admission marker: {error}");
        return ExitCode::from(2);
    }
    let deadline = Instant::now() + Duration::from_secs(seconds.unwrap_or(30));
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
        let _ = std::hint::black_box(&*canary);
    }
    ExitCode::SUCCESS
}

/// MPS9 synthetic shielded target: allocates a random in-memory canary,
/// writes its identity to READY_FILE (PID + hex canary), then stays alive
/// (default 30s) so untrusted probes can attempt local task-port operations
/// against it. No real browser/session data; no networking.
fn do_shield_target(
    ready_file: &Path,
    seconds: Option<u64>,
    protected_file: Option<&Path>,
) -> ExitCode {
    // Heap allocation gives the Linux same-UID ptrace oracle a stable address
    // for the target's complete lifetime. It is synthetic test metadata only.
    let mut canary = Box::new([0u8; SHIELD_CANARY_LEN]);
    // Fresh random canary per invocation from the system entropy source.
    if let Ok(mut random) = File::open("/dev/urandom") {
        use std::io::Read as _;
        let _ = random.read_exact(&mut *canary);
    }
    let hex = canary
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let pid = std::process::id();
    // The LPS1 parent-only ptrace oracle needs an exact synthetic address to
    // prove its OFF baseline. This is metadata about a random test canary, not
    // a browser secret; the oracle reports only match/no-match, never bytes.
    let ready = format!("{pid} {hex} 0x{:x}\n", canary.as_ptr() as usize);
    if let Err(error) = std::fs::write(ready_file, ready) {
        eprintln!("guard-test-probe: cannot write shield-target ready file: {error}");
        return ExitCode::from(2);
    }
    println!("SHIELD_TARGET pid={pid} ready");
    let _ = std::io::stdout().flush();
    let seconds = seconds.unwrap_or(30);
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
        // Keep the canary reachable so a successful vm_read would find it.
        let _ = std::hint::black_box(&*canary);
        if let Some(protected) = protected_file {
            match std::fs::read(protected) {
                Ok(bytes) => {
                    println!("SHIELD_TARGET_READ ok bytes={}", bytes.len());
                    let _ = std::io::stdout().flush();
                }
                Err(error) => {
                    println!("SHIELD_TARGET_READ denied error={error}");
                    let _ = std::io::stdout().flush();
                }
            }
        }
    }
    ExitCode::SUCCESS
}

fn self_task_port() -> u32 {
    // SAFETY: mach_task_self() has no preconditions and returns the caller's
    // own task port name.
    unsafe { mach_task_self() }
}

/// MPS9 untrusted task-port probe: attempt to obtain a task control or task
/// read port for TARGET_PID. Prints the kernel result. No networking.
fn do_probe_task(target_pid: i32, kind: &str) -> ExitCode {
    let mut port: u32 = 0;
    let result = match kind {
        "control" => unsafe { task_for_pid(self_task_port(), target_pid, &mut port) },
        "read" => unsafe { task_read_for_pid(self_task_port(), target_pid, &mut port) },
        _ => {
            eprintln!("guard-test-probe: probe-task kind must be control or read");
            return ExitCode::from(2);
        }
    };
    println!("PROBE_TASK kind={kind} target={target_pid} result={result} port={port}");
    if result == 0 && port != 0 {
        eprintln!("guard-test-probe: UNEXPECTED: usable task port obtained");
        return ExitCode::from(3);
    }
    if result == 0 {
        return ExitCode::SUCCESS;
    }
    ExitCode::from(4)
}

/// MPS9 memory probe: after attempting task read acquisition, scan a bounded
/// range of the target's address space with vm_read and report whether any
/// readable page was recovered (the canary itself is never dumped). When the
/// task read port was denied, the scan cannot run at all, so `recovered_pages
/// == 0` means no usable task-read capability was acquired (the denial was
/// already proven by `probe-task read` exit 4); it is NOT a proof that the
/// canary specifically is unreachable in every mapping.
fn do_probe_memory(target_pid: i32) -> ExitCode {
    let mut port: u32 = 0;
    let read_result = unsafe { task_read_for_pid(mach_task_self(), target_pid, &mut port) };
    let mut recovered_pages = 0u64;
    let mut page: u64 = 0x1000; // skip the null page
    const PAGE_SIZE: u64 = 0x1000;
    while page < 0x10_0000_0000 {
        let mut data: u32 = 0;
        let mut count: u32 = 0;
        let result = unsafe { vm_read(port, page, PAGE_SIZE, &mut data, &mut count) };
        if result == 0 && count > 0 {
            recovered_pages += 1;
            // SAFETY: vm_read returned a kernel-owned buffer of `count` bytes.
            let bytes = unsafe { std::slice::from_raw_parts(data as *const u8, count as usize) };
            let _ = std::hint::black_box(bytes);
            unsafe { vm_deallocate(self_task_port(), data as u64, count as u64) };
            if recovered_pages >= 64 {
                break;
            }
        }
        page += PAGE_SIZE;
    }
    println!(
        "PROBE_MEMORY target={target_pid} task_read_result={read_result} recovered_pages={recovered_pages}"
    );
    if recovered_pages == 0 {
        ExitCode::SUCCESS
    } else {
        // Any readable page proves a usable task-read capability exists;
        // report as recoverable (the canary-specific assertion is the
        // probe-task read denial above).
        ExitCode::from(5)
    }
}

#[cfg(target_os = "macos")]
mod mach {
    #![allow(non_camel_case_types)]
    pub type kern_return_t = i32;
    pub type mach_port_t = u32;
    pub type mach_vm_address_t = u64;
    pub type mach_vm_size_t = u64;
    pub type vm_offset_t = u32;
    pub type mach_msg_type_number_t = u32;
    #[allow(dead_code)]
    pub type vm_size_t = u64;

    #[link(name = "System", kind = "framework")]
    extern "C" {
        pub fn mach_task_self() -> mach_port_t;
        pub fn task_for_pid(target: mach_port_t, pid: i32, task: *mut mach_port_t)
            -> kern_return_t;
        pub fn task_read_for_pid(
            target: mach_port_t,
            pid: i32,
            task: *mut mach_port_t,
        ) -> kern_return_t;
        pub fn vm_read(
            task: mach_port_t,
            address: mach_vm_address_t,
            size: mach_vm_size_t,
            data: *mut vm_offset_t,
            data_count: *mut mach_msg_type_number_t,
        ) -> kern_return_t;
        pub fn vm_deallocate(
            task: mach_port_t,
            address: mach_vm_address_t,
            size: mach_vm_size_t,
        ) -> kern_return_t;
    }
}

#[cfg(not(target_os = "macos"))]
mod mach {
    #![allow(non_camel_case_types)]
    pub type kern_return_t = i32;
    pub type mach_port_t = u32;
    pub type mach_vm_address_t = u64;
    pub type mach_vm_size_t = u64;
    pub type vm_offset_t = u32;
    pub type mach_msg_type_number_t = u32;
    // Placeholder UAPI mirror kept symmetric with the macOS module; unused on
    // non-macOS builds where the task_read probe is a stub.
    #[allow(dead_code)]
    pub type vm_size_t = u64;
}

#[cfg(target_os = "macos")]
use mach::{mach_task_self, task_for_pid, task_read_for_pid, vm_deallocate, vm_read};

#[cfg(not(target_os = "macos"))]
unsafe fn task_for_pid(
    _t: mach::mach_port_t,
    _p: i32,
    _task: *mut mach::mach_port_t,
) -> mach::kern_return_t {
    -5
}
#[cfg(not(target_os = "macos"))]
unsafe fn task_read_for_pid(
    _t: mach::mach_port_t,
    _p: i32,
    _task: *mut mach::mach_port_t,
) -> mach::kern_return_t {
    -5
}
#[cfg(not(target_os = "macos"))]
unsafe fn vm_read(
    _t: mach::mach_port_t,
    _a: mach::mach_vm_address_t,
    _s: mach::mach_vm_size_t,
    _d: *mut mach::vm_offset_t,
    _c: *mut mach::mach_msg_type_number_t,
) -> mach::kern_return_t {
    -5
}
#[cfg(not(target_os = "macos"))]
unsafe fn vm_deallocate(
    _t: mach::mach_port_t,
    _a: mach::mach_vm_address_t,
    _s: mach::mach_vm_size_t,
) -> mach::kern_return_t {
    -5
}
#[cfg(not(target_os = "macos"))]
unsafe fn mach_task_self() -> mach::mach_port_t {
    0
}

fn do_read(path: &Path) -> ExitCode {
    match std::fs::read(path) {
        Ok(bytes) => {
            let _ = std::io::stdout().write_all(&bytes);
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
        Err(error) => report_failure("open/read", path, &error),
    }
}

/// Write synthetic fixture content through THIS process's identity. Used by
/// privileged harnesses so new protected-tree content is created by the
/// enrolled browser identity (the harness shell is an unknown process and
/// would be denied by the firewall, which is exactly the behavior under test).
fn do_write_file(path: &Path, content: &[u8]) -> ExitCode {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => {
            return report_failure(
                "resolve parent dir",
                path,
                &std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent directory"),
            )
        }
    };
    if let Err(error) = std::fs::create_dir_all(parent) {
        return report_failure("create parent dirs", path, &error);
    }
    match std::fs::write(path, content) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => report_failure("write fixture", path, &error),
    }
}

/// Read one byte in this process, then have a child read the same fixture.
/// This is a local process-tree lease probe: bytes are discarded and the
/// command has no networking or persistence behavior.
fn do_read_then_child_read(path: &Path) -> ExitCode {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => return report_failure("open root read", path, &error),
    };
    let mut byte = [0_u8; 1];
    if let Err(error) = file.read_exact(&mut byte) {
        return report_failure("root read", path, &error);
    }
    drop(file);
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => return report_failure("resolve child executable", path, &error),
    };
    match Command::new(executable)
        .arg("read")
        .arg(path)
        .stdout(std::process::Stdio::null())
        .status()
    {
        Ok(status) if status.success() => {
            println!("{{\"root_read\":true,\"descendant_read\":true}}");
            ExitCode::SUCCESS
        }
        Ok(status) => {
            eprintln!("guard-test-probe: descendant read exited with {status}");
            ExitCode::FAILURE
        }
        Err(error) => report_failure("spawn descendant reader", path, &error),
    }
}

fn do_mmap(path: &Path) -> ExitCode {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) => return report_failure("open for mmap", path, &error),
    };
    let len = match file.metadata() {
        Ok(metadata) => metadata.len() as usize,
        Err(error) => return report_failure("fstat", path, &error),
    };
    if len == 0 {
        println!("guard-test-probe: mmap ok (empty file)");
        return ExitCode::SUCCESS;
    }

    // SAFETY: `file` remains alive, the mapping is read-only, and its length is
    // exactly the current file size. The returned region is unmapped below.
    unsafe {
        let pointer = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        );
        if pointer == libc::MAP_FAILED {
            eprintln!("guard-test-probe: mmap {} failed", path.display());
            return ExitCode::FAILURE;
        }
        let bytes = std::slice::from_raw_parts(pointer.cast::<u8>(), len);
        if let Some(canary) = extract_canary(bytes) {
            println!("{canary}");
        } else {
            println!("guard-test-probe: mmap ok; no synthetic canary found");
        }
        libc::munmap(pointer, len);
    }
    ExitCode::SUCCESS
}

fn do_sqlite(path: &Path) -> ExitCode {
    match read_sqlite_canary(path) {
        Ok(canary) => {
            println!("{canary}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!(
                "guard-test-probe: SQLite read {} failed: {error}",
                path.display()
            );
            ExitCode::FAILURE
        }
    }
}

fn do_copy_read(source: &Path, destination: &Path) -> ExitCode {
    if let Err(error) = std::fs::copy(source, destination) {
        return report_failure("copy source", source, &error);
    }
    do_read(destination)
}

fn do_child_read(path: &Path) -> ExitCode {
    let executable = match std::env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            eprintln!("guard-test-probe: cannot resolve current executable: {error}");
            return ExitCode::FAILURE;
        }
    };
    match Command::new(executable).arg("read").arg(path).output() {
        Ok(output) => {
            let _ = std::io::stdout().write_all(&output.stdout);
            let _ = std::io::stderr().write_all(&output.stderr);
            if output.status.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("guard-test-probe: child launch failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn do_proc_fd(pid: &str, fd: &str) -> ExitCode {
    if !pid.bytes().all(|byte| byte.is_ascii_digit())
        || !fd.bytes().all(|byte| byte.is_ascii_digit())
    {
        eprintln!("guard-test-probe: PID and FD must be decimal integers");
        return ExitCode::from(2);
    }
    do_read(&PathBuf::from(format!("/proc/{pid}/fd/{fd}")))
}

fn do_hold_fd(path: &Path, ready_file: &Path) -> ExitCode {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => return report_failure("open for hold-fd", path, &error),
    };
    if let Err(error) = std::fs::write(
        ready_file,
        format!("{} {}\n", std::process::id(), file.as_raw_fd()),
    ) {
        return report_failure("write readiness file", ready_file, &error);
    }

    // Keep the descriptor alive long enough for the separate `/proc/PID/fd/N`
    // probe. Reading one byte also proves this authorized opener has a usable fd.
    let mut byte = [0_u8; 1];
    if let Err(error) = file.read(&mut byte) {
        return report_failure("read held fd", path, &error);
    }
    std::thread::sleep(Duration::from_secs(60));
    ExitCode::SUCCESS
}

fn do_exfil_unix(path: &Path, socket: &Path, sqlite: bool) -> ExitCode {
    let canary = if sqlite {
        match read_sqlite_canary(path) {
            Ok(canary) => canary,
            Err(error) => {
                eprintln!(
                    "guard-test-probe: SQLite read {} failed before local send: {error}",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        }
    } else {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => return report_failure("read before local send", path, &error),
        };
        match extract_canary(&bytes) {
            Some(canary) => canary,
            None => {
                eprintln!(
                    "guard-test-probe: no synthetic canary in {}; nothing sent",
                    path.display()
                );
                return ExitCode::FAILURE;
            }
        }
    };

    let mut stream = match UnixStream::connect(socket) {
        Ok(stream) => stream,
        Err(error) => return report_failure("connect local Unix sink", socket, &error),
    };
    if let Err(error) = stream.write_all(canary.as_bytes()) {
        return report_failure("write local Unix sink", socket, &error);
    }
    ExitCode::SUCCESS
}

/// Empirically measure the documented topology watcher -> fanotify remark
/// interval. Every payload is a synthetic canary and remains local. Successful
/// reads are counted but their bytes are never printed.
fn do_topology_race(target: &Path, staging_dir: &Path, iterations: u64) -> ExitCode {
    if let Err(error) = std::fs::create_dir_all(staging_dir) {
        return report_failure(
            "create topology-race staging directory",
            staging_dir,
            &error,
        );
    }
    let mut recovered = 0_u64;
    let mut denied = 0_u64;
    let mut other_errors = 0_u64;
    let mut convergence_us = Vec::new();

    for iteration in 0..iterations {
        let replacement = staging_dir.join(format!(
            ".sdf-topology-race-{}-{iteration}",
            std::process::id()
        ));
        let payload = format!("SDF_CANARY_TOPOLOGY_RACE_{iteration}");
        if let Err(error) = std::fs::write(&replacement, payload.as_bytes()) {
            return report_failure("write topology-race replacement", &replacement, &error);
        }
        if let Err(error) = std::fs::rename(&replacement, target) {
            return report_failure("rename topology-race replacement", target, &error);
        }

        let started = Instant::now();
        match std::fs::read(target) {
            Ok(bytes) => {
                if bytes != payload.as_bytes() {
                    eprintln!("guard-test-probe: topology-race read unexpected synthetic payload");
                    return ExitCode::FAILURE;
                }
                recovered += 1;
                // Measure convergence only after a demonstrated immediate
                // recovery. Bound the loop so a broken watcher cannot hang.
                let deadline = started + Duration::from_secs(2);
                loop {
                    match std::fs::read(target) {
                        Err(error) if is_access_denial(&error) => {
                            convergence_us.push(started.elapsed().as_micros() as u64);
                            break;
                        }
                        Err(_) => {
                            other_errors += 1;
                            break;
                        }
                        Ok(_) if Instant::now() < deadline => std::thread::yield_now(),
                        Ok(_) => {
                            other_errors += 1;
                            break;
                        }
                    }
                }
            }
            Err(error) if is_access_denial(&error) => denied += 1,
            Err(_) => other_errors += 1,
        }
    }

    convergence_us.sort_unstable();
    let p50 = percentile(&convergence_us, 50);
    let p95 = percentile(&convergence_us, 95);
    let p99 = percentile(&convergence_us, 99);
    let maximum = convergence_us.last().copied().unwrap_or(0);
    println!(
        "{{\"iterations\":{iterations},\"successful_unauthorized_reads\":{recovered},\"denied_reads\":{denied},\"other_errors\":{other_errors},\"time_to_protection_us\":{{\"samples\":{},\"p50\":{p50},\"p95\":{p95},\"p99\":{p99},\"max\":{maximum}}}}}",
        convergence_us.len()
    );
    if other_errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Measure repeated open latency without printing file contents. The command
/// intentionally performs no networking and reports only aggregate counters.
fn do_open_bench(path: &Path, iterations: u64) -> ExitCode {
    let overall = Instant::now();
    let mut successful = 0_u64;
    let mut denied = 0_u64;
    let mut other_errors = 0_u64;
    let mut latency_ns = Vec::with_capacity(iterations.min(1_000_000) as usize);

    for _ in 0..iterations {
        let started = Instant::now();
        match File::open(path) {
            Ok(file) => {
                drop(file);
                successful += 1;
            }
            Err(error) if is_access_denial(&error) => denied += 1,
            Err(_) => other_errors += 1,
        }
        latency_ns.push(started.elapsed().as_nanos().min(u64::MAX as u128) as u64);
    }

    latency_ns.sort_unstable();
    let elapsed_ns = overall.elapsed().as_nanos().min(u64::MAX as u128) as u64;
    let opens_per_sec = if elapsed_ns == 0 {
        0
    } else {
        ((iterations as u128 * 1_000_000_000_u128) / elapsed_ns as u128) as u64
    };
    println!(
        "{{\"iterations\":{iterations},\"successful\":{successful},\"denied\":{denied},\"other_errors\":{other_errors},\"elapsed_ns\":{elapsed_ns},\"opens_per_sec\":{opens_per_sec},\"latency_ns\":{{\"p50\":{},\"p95\":{},\"p99\":{},\"max\":{}}}}}",
        percentile(&latency_ns, 50),
        percentile(&latency_ns, 95),
        percentile(&latency_ns, 99),
        latency_ns.last().copied().unwrap_or(0),
    );
    if other_errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Investigate the narrow alias case where a replacement inode is hardlinked
/// outside the protected namespace before it is renamed into place. No bytes
/// are printed; the command only reports whether the external alias opened.
fn do_alias_race(
    target: &Path,
    staging_dir: &Path,
    external_alias: &Path,
    iterations: u64,
) -> ExitCode {
    if let Err(error) = std::fs::create_dir_all(staging_dir) {
        return report_failure("create alias-race staging directory", staging_dir, &error);
    }
    let mut recovered = 0_u64;
    let mut denied = 0_u64;
    let mut other_errors = 0_u64;
    for iteration in 0..iterations {
        let replacement = staging_dir.join(format!(
            ".sdf-alias-race-{}-{iteration}",
            std::process::id()
        ));
        let payload = format!("SDF_CANARY_ALIAS_RACE_{iteration}");
        if let Err(error) = std::fs::write(&replacement, payload.as_bytes()) {
            return report_failure("write alias-race replacement", &replacement, &error);
        }
        let _ = std::fs::remove_file(external_alias);
        if let Err(error) = std::fs::hard_link(&replacement, external_alias) {
            return report_failure("create alias-race hardlink", external_alias, &error);
        }
        if let Err(error) = std::fs::rename(&replacement, target) {
            return report_failure("rename alias-race replacement", target, &error);
        }
        match std::fs::read(external_alias) {
            Ok(bytes) if bytes == payload.as_bytes() => recovered += 1,
            Ok(_) => other_errors += 1,
            Err(error) if is_access_denial(&error) => denied += 1,
            Err(_) => other_errors += 1,
        }
    }
    let _ = std::fs::remove_file(external_alias);
    println!(
        "{{\"iterations\":{iterations},\"successful_unauthorized_reads\":{recovered},\"denied_reads\":{denied},\"other_errors\":{other_errors}}}"
    );
    if other_errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Model an enrolled browser publishing a new sensitive inode, opening it
/// once, and immediately renaming it outside the browser namespace. The
/// executable running this command must be explicitly enrolled by the test.
/// Contents are never read or printed.
fn do_promote_rename(staged: &Path, target: &Path, external: &Path) -> ExitCode {
    if let Err(error) = std::fs::rename(staged, target) {
        return report_failure("rename staged inode into protected path", target, &error);
    }
    let file = match File::open(target) {
        Ok(file) => file,
        Err(error) => return report_failure("authorized first open", target, &error),
    };
    drop(file);
    if let Err(error) = std::fs::rename(target, external) {
        return report_failure("rename promoted inode outside namespace", external, &error);
    }
    println!("{{\"authorized_first_open\":true,\"renamed_outside\":true}}");
    ExitCode::SUCCESS
}

/// Attempt a protected first open, rename the same inode outside the protected
/// namespace, and retry immediately in one unauthorized process. No file bytes
/// are read or printed; a successful second open is reported as a recovery.
fn do_deny_rename_retry(target: &Path, external: &Path) -> ExitCode {
    let first_denied = match File::open(target) {
        Err(error) if is_access_denial(&error) => true,
        Ok(file) => {
            drop(file);
            false
        }
        Err(error) => return report_failure("first protected open", target, &error),
    };
    if let Err(error) = std::fs::rename(target, external) {
        return report_failure("rename denied inode outside namespace", external, &error);
    }
    let second_denied = match File::open(external) {
        Err(error) if is_access_denial(&error) => true,
        Ok(file) => {
            drop(file);
            false
        }
        Err(error) => return report_failure("second outside open", external, &error),
    };
    println!(
        "{{\"first_denied\":{first_denied},\"renamed_outside\":true,\"second_denied\":{second_denied},\"successful_unauthorized_opens\":{}}}",
        u8::from(!first_denied) + u8::from(!second_denied)
    );
    if first_denied && second_denied {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Move an inode through a protected pathname without opening it there, then
/// try the external name. This measures the deliberate FAN_OPEN_PERM boundary:
/// an open-only backend does not observe the two rename operations.
fn do_transit_rename(staged: &Path, target: &Path, external: &Path) -> ExitCode {
    if let Err(error) = std::fs::rename(staged, target) {
        return report_failure("rename transit inode into protected path", target, &error);
    }
    if let Err(error) = std::fs::rename(target, external) {
        return report_failure("rename transit inode outside namespace", external, &error);
    }
    let outside_opened = match File::open(external) {
        Ok(file) => {
            drop(file);
            true
        }
        Err(error) if is_access_denial(&error) => false,
        Err(error) => {
            return report_failure("open transit inode outside namespace", external, &error)
        }
    };
    println!(
        "{{\"opened_while_protected\":false,\"renamed_outside\":true,\"outside_opened\":{outside_opened}}}"
    );
    ExitCode::SUCCESS
}

fn is_access_denial(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(code) if code == libc::EACCES || code == libc::EPERM)
}

/// R1 zero-settle adversarial stress (LFH2 Step 3): the exact attacker path
/// `unprotected temp → rename into protected sensitive name → immediately
/// rename out → immediate unknown open`, with NO settle between the renames
/// and the open. The temp object lives OUTSIDE the protected tree and is
/// created by the harness BEFORE guardd starts (its creation is not gated);
/// each iteration reuses the same inode: staging → protected name → outside
/// name → immediate open attempt → back to staging. Successful opens are
/// counted but their bytes are never read or printed. The harness asserts
/// `successful_unauthorized_reads == 0` in strict mode.
#[cfg(target_os = "linux")]
fn do_rename_out_race(target: &Path, outside_dir: &Path, temp: &Path, iterations: u64) -> ExitCode {
    let mut recovered = 0_u64;
    let mut denied = 0_u64;
    let mut other_errors = 0_u64;
    for iteration in 0..iterations {
        let outside = outside_dir.join(format!(".sdf-race-out-{iteration}"));
        if let Err(error) = std::fs::rename(temp, target) {
            return report_failure("rename-in to protected name", target, &error);
        }
        if let Err(error) = std::fs::rename(target, &outside) {
            return report_failure("rename-out to outside name", &outside, &error);
        }
        match std::fs::read(&outside) {
            Ok(_bytes) => recovered += 1,
            Err(error) if is_access_denial(&error) => denied += 1,
            Err(_) => other_errors += 1,
        }
        if let Err(error) = std::fs::rename(&outside, temp) {
            return report_failure("return object to staging", temp, &error);
        }
    }
    println!(
        "{{\"iterations\":{iterations},\"successful_unauthorized_reads\":{recovered},\"denied_reads\":{denied},\"other_errors\":{other_errors}}}"
    );
    if other_errors == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// R4 live mark-loss helper: find the target process's fanotify PERMISSION
/// group (the fd whose fdinfo carries `fanotify sdev:` filesystem marks),
/// duplicate the exact group fd via `pidfd_open` + `pidfd_getfd`, and then
/// `FAN_MARK_REMOVE | FAN_MARK_FILESYSTEM` (remove) or
/// `FAN_MARK_ADD | FAN_MARK_FILESYSTEM` (restore) the filesystem mark for
/// PATH — a REAL kernel mark mutation on the live group, not a state
/// injection. Prints the fdinfo `fanotify sdev:` count before/after so the
/// harness can verify the kernel actually dropped/restored the mark.
#[cfg(target_os = "linux")]
fn do_fsmark(pid: Option<i32>, known_fd: Option<i32>, path: &Path, restore: bool) -> ExitCode {
    // SYS_pidfd_open = 434, SYS_pidfd_getfd = 438 (x86_64 and aarch64).
    const SYS_PIDFD_OPEN: libc::c_long = 434;
    const SYS_PIDFD_GETFD: libc::c_long = 438;

    let Some(pid) = pid else {
        eprintln!("guard-test-probe: fsmark PID must be an integer");
        return ExitCode::from(2);
    };
    if pid <= 0 {
        eprintln!("guard-test-probe: fsmark PID must be positive");
        return ExitCode::from(2);
    }

    // The permission group fd: passed explicitly when known (the remove call
    // prints it; after marks are removed the scan cannot find the group).
    // Otherwise scan: FAN_CLASS_CONTENT bit in the `fanotify flags:` line
    // (the topology group is FAN_CLASS_NOTIF and never matches), with the
    // `fanotify sdev:` line as fallback.
    let fanotify_fd = match known_fd {
        Some(fd) if fd > 0 => fd,
        _ => {
            let mut found: Option<i32> = None;
            let proc_fd = PathBuf::from(format!("/proc/{pid}/fd"));
            for entry in std::fs::read_dir(&proc_fd).ok().into_iter().flatten() {
                let Ok(entry) = entry else { continue };
                let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
                    continue;
                };
                let Ok(fdinfo) = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) else {
                    continue;
                };
                let flags = fdinfo
                    .lines()
                    .find(|line| line.starts_with("fanotify flags:"))
                    .and_then(|line| {
                        let value = line.split_once(':').map(|(_, v)| v.trim()).unwrap_or("");
                        u32::from_str_radix(value.trim_start_matches("0x"), 16).ok()
                    })
                    .unwrap_or(0);
                // FAN_CLASS_CONTENT = 0x4.
                if flags & 0x4 != 0 || fdinfo.contains("fanotify sdev:") {
                    found = Some(fd);
                    break;
                }
            }
            match found {
                Some(fd) => fd,
                None => {
                    eprintln!(
                        "guard-test-probe: no fanotify permission-group fd found for pid {pid} \
                         (is the target the strict-mode guardd?)"
                    );
                    return ExitCode::FAILURE;
                }
            }
        }
    };
    let sdev_before = count_sdev_lines(pid, fanotify_fd);

    // SAFETY: pidfd_open/getfd are raw syscalls with the documented UAPI
    // signatures; results are checked before use.
    let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid as libc::c_int, 0) };
    if pidfd < 0 {
        eprintln!(
            "guard-test-probe: pidfd_open({pid}) failed: {}",
            std::io::Error::last_os_error()
        );
        return ExitCode::FAILURE;
    }
    let dup = unsafe { libc::syscall(SYS_PIDFD_GETFD, pidfd, fanotify_fd, 0) };
    if dup < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(pidfd as libc::c_int) };
        eprintln!(
            "guard-test-probe: pidfd_getfd({pid}, fd {fanotify_fd}) failed: {error} \
             (ptrace policy? check /proc/sys/kernel/yama/ptrace_scope)"
        );
        return ExitCode::FAILURE;
    }

    let c = match std::ffi::CString::new(path.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => {
            unsafe { libc::close(dup as libc::c_int) };
            unsafe { libc::close(pidfd as libc::c_int) };
            eprintln!("guard-test-probe: invalid path for fsmark");
            return ExitCode::from(2);
        }
    };
    let action = if restore {
        libc::FAN_MARK_ADD
    } else {
        libc::FAN_MARK_REMOVE
    };
    // RESTORE must use the real permission mask (FAN_OPEN_PERM): a mask-0
    // FAN_MARK_ADD would add a mask-0 mark that never gates opens. REMOVE
    // tries mask 0 first (remove the fs-scope mark), falling back to the
    // permission mask on EINVAL.
    let mut rc = if restore {
        unsafe {
            libc::fanotify_mark(
                dup as libc::c_int,
                (action | libc::FAN_MARK_FILESYSTEM) as libc::c_uint,
                libc::FAN_OPEN_PERM,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        }
    } else {
        unsafe {
            libc::fanotify_mark(
                dup as libc::c_int,
                (action | libc::FAN_MARK_FILESYSTEM) as libc::c_uint,
                0,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        }
    };
    if rc < 0 && !restore {
        rc = unsafe {
            libc::fanotify_mark(
                dup as libc::c_int,
                (action | libc::FAN_MARK_FILESYSTEM) as libc::c_uint,
                libc::FAN_OPEN_PERM,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        };
    }
    let op_result = if rc < 0 {
        format!("failed: {}", std::io::Error::last_os_error())
    } else {
        "ok".to_owned()
    };
    let sdev_after = count_sdev_lines(pid, fanotify_fd);
    unsafe { libc::close(dup as libc::c_int) };
    unsafe { libc::close(pidfd as libc::c_int) };
    println!(
        "fsmark: pid={pid} fanotify_fd={fanotify_fd} action={} result={op_result} sdev_before={sdev_before} sdev_after={sdev_after}",
        if restore { "restore" } else { "remove" }
    );
    if rc < 0 {
        return ExitCode::FAILURE;
    }
    let changed = if restore {
        sdev_after > sdev_before
    } else {
        sdev_after < sdev_before
    };
    if changed {
        ExitCode::SUCCESS
    } else {
        eprintln!("guard-test-probe: fdinfo filesystem-mark count did not change as expected");
        ExitCode::FAILURE
    }
}

/// Count `fanotify sdev:` (filesystem-scope mark) lines in the target's
/// fdinfo for `fd`. Reads the target's fdinfo directly (same ptrace access
/// as the fd scan); returns 0 on any read error.
#[cfg(target_os = "linux")]
fn count_sdev_lines(pid: i32, fd: i32) -> usize {
    std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))
        .map(|info| {
            info.lines()
                .filter(|line| line.contains("fanotify sdev:"))
                .count()
        })
        .unwrap_or(0)
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() - 1) * percentile) / 100;
    sorted[index]
}

fn read_sqlite_canary(path: &Path) -> rusqlite::Result<String> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let value: String = connection.query_row(
        "SELECT value FROM sdf_canary ORDER BY rowid LIMIT 1",
        [],
        |row| row.get(0),
    )?;
    extract_canary(value.as_bytes()).ok_or(rusqlite::Error::InvalidQuery)
}

fn extract_canary(bytes: &[u8]) -> Option<String> {
    let start = bytes
        .windows(CANARY_PREFIX.len())
        .position(|window| window == CANARY_PREFIX)?;
    let tail = &bytes[start..bytes.len().min(start + MAX_CANARY_LEN)];
    let length = tail
        .iter()
        .position(|byte| !is_canary_byte(*byte))
        .unwrap_or(tail.len());
    if length <= CANARY_PREFIX.len() {
        return None;
    }
    String::from_utf8(tail[..length].to_vec()).ok()
}

fn is_canary_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn report_failure(operation: &str, path: &Path, error: &std::io::Error) -> ExitCode {
    eprintln!(
        "guard-test-probe: {operation} {} failed: {error} (errno {:?})",
        path.display(),
        error.raw_os_error()
    );
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_the_synthetic_canary_token() {
        assert_eq!(
            extract_canary(b"prefix SDF_CANARY_cookie-123\0secret-after"),
            Some("SDF_CANARY_cookie-123".to_owned())
        );
    }

    #[test]
    fn rejects_missing_or_empty_canary() {
        assert_eq!(extract_canary(b"ordinary browser data"), None);
        assert_eq!(extract_canary(CANARY_PREFIX), None);
    }

    #[test]
    fn reads_canary_from_synthetic_sqlite_table() {
        let directory = tempfile::tempdir().expect("temp dir");
        let database = directory.path().join("Cookies");
        let connection = rusqlite::Connection::open(&database).expect("create SQLite fixture");
        connection
            .execute(
                "CREATE TABLE sdf_canary(kind TEXT NOT NULL, value TEXT NOT NULL)",
                [],
            )
            .expect("create canary table");
        connection
            .execute(
                "INSERT INTO sdf_canary VALUES ('synthetic-cookie', ?1)",
                ["SDF_CANARY_SQLITE_TEST"],
            )
            .expect("insert canary");
        drop(connection);

        assert_eq!(
            read_sqlite_canary(&database).expect("read canary"),
            "SDF_CANARY_SQLITE_TEST"
        );
    }

    #[test]
    fn percentile_handles_empty_and_sorted_samples() {
        assert_eq!(percentile(&[], 95), 0);
        assert_eq!(percentile(&[10, 20, 30, 40, 50], 50), 30);
        assert_eq!(percentile(&[10, 20, 30, 40, 50], 99), 40);
    }
}
