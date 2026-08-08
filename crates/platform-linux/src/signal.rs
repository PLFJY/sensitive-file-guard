//! SIGINT/SIGTERM handling for clean daemon shutdown.
//!
//! Handlers are installed WITHOUT `SA_RESTART` so that a blocking `read` on the
//! fanotify fd returns `EINTR` and the daemon loop can observe the shutdown
//! flag and exit promptly. (If `guardd`'s fanotify fd closes, outstanding
//! permission events become allowed, so prompt shutdown + restart matters.)

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle(_sig: libc::c_int) {
    // Async-signal-safe: a single atomic store.
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install SIGINT/SIGTERM handlers that interrupt blocking syscalls.
///
/// Best-effort: ignores `sigaction` errors (a failure here is non-fatal; the
/// daemon can still be killed, which closes the fanotify fd).
pub fn install_shutdown_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        // sa_sigaction holds the handler address (union with sa_handler when
        // SA_SIGINFO is not set).
        sa.sa_sigaction = handle as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0; // deliberately no SA_RESTART
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Reset the shutdown flag (useful for tests that re-invoke the loop).
pub fn reset() {
    SHUTDOWN.store(false, Ordering::SeqCst);
}
