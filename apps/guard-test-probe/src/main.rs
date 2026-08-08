//! `guard-test-probe` — tiny test binary for fanotify PoC tests.
//!
//! Opens/reads a path and reports success or the OS error. Used as the
//! enrolled (allowed) and, via a different executable identity, the denied
//! opener. Contains NO network code.
//!
//! Subcommands:
//! - `read <PATH>` — open + read the file, print bytes to stdout.
//! - `mmap <PATH>` — open + mmap the file, read first byte, print it. If the
//!   open is denied by fanotify (no fd acquired), mmap cannot succeed.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: guard-test-probe <read|mmap> <PATH>");
        return ExitCode::from(2);
    }
    let path = PathBuf::from(&args[2]);

    match args[1].as_str() {
        "read" => do_read(&path),
        "mmap" => do_mmap(&path),
        _ => {
            eprintln!("usage: guard-test-probe <read|mmap> <PATH>");
            ExitCode::from(2)
        }
    }
}

fn do_read(path: &PathBuf) -> ExitCode {
    match std::fs::read(path) {
        Ok(bytes) => {
            let _ = std::io::stdout().write_all(&bytes);
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "guard-test-probe: open/read {} failed: {} (errno {:?})",
                path.display(),
                e,
                e.raw_os_error()
            );
            ExitCode::FAILURE
        }
    }
}

fn do_mmap(path: &PathBuf) -> ExitCode {
    use std::os::unix::io::AsRawFd;
    // Open the file. If fanotify denies the open, this fails and we never
    // reach mmap — proving that a denied open does not yield an fd.
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "guard-test-probe: open (for mmap) {} failed: {} (errno {:?})",
                path.display(),
                e,
                e.raw_os_error()
            );
            return ExitCode::FAILURE;
        }
    };
    let fd = file.as_raw_fd();
    let len = match file.metadata() {
        Ok(m) => m.len() as usize,
        Err(e) => {
            eprintln!("guard-test-probe: fstat failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if len == 0 {
        // Empty file — mmap of 0 bytes is invalid; treat as success (open
        // succeeded, no bytes to map).
        println!("guard-test-probe: mmap ok (empty file)");
        return ExitCode::SUCCESS;
    }
    // SAFETY: fd is a valid read-only file descriptor; len is the file size.
    // We map exactly one page of the file and read the first byte.
    unsafe {
        let ptr = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        );
        if ptr == libc::MAP_FAILED {
            eprintln!("guard-test-probe: mmap failed");
            return ExitCode::FAILURE;
        }
        let byte = *(ptr as *const u8);
        libc::munmap(ptr, len);
        println!("guard-test-probe: mmap ok, first byte={:#x}", byte);
    }
    ExitCode::SUCCESS
}
