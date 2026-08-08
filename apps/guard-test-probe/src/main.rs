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
use std::time::Duration;

const CANARY_PREFIX: &[u8] = b"SDF_CANARY_";
const MAX_CANARY_LEN: usize = 256;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("read") if args.len() == 3 => do_read(Path::new(&args[2])),
        Some("mmap") if args.len() == 3 => do_mmap(Path::new(&args[2])),
        Some("sqlite") if args.len() == 3 => do_sqlite(Path::new(&args[2])),
        Some("copy-read") if args.len() == 4 => {
            do_copy_read(Path::new(&args[2]), Path::new(&args[3]))
        }
        Some("child-read") if args.len() == 3 => do_child_read(Path::new(&args[2])),
        Some("proc-fd") if args.len() == 4 => do_proc_fd(&args[2], &args[3]),
        Some("hold-fd") if args.len() == 4 => do_hold_fd(Path::new(&args[2]), Path::new(&args[3])),
        Some("exfil-unix") if args.len() == 4 => {
            do_exfil_unix(Path::new(&args[2]), Path::new(&args[3]), false)
        }
        Some("sqlite-exfil-unix") if args.len() == 4 => {
            do_exfil_unix(Path::new(&args[2]), Path::new(&args[3]), true)
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
           mmap PATH\n\
           sqlite DATABASE\n\
           copy-read SOURCE DESTINATION\n\
           child-read PATH\n\
           proc-fd PID FD\n\
           hold-fd PATH READY_FILE\n\
           exfil-unix PATH SOCKET\n\
           sqlite-exfil-unix DATABASE SOCKET"
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
}
