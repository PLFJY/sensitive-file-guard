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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("noop") if args.len() == 2 => ExitCode::SUCCESS,
        Some("read") if args.len() == 3 => do_read(Path::new(&args[2])),
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
           noop\n\
           read PATH\n\
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
           transit-rename STAGED TARGET EXTERNAL"
    );
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
