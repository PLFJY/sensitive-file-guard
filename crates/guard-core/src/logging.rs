//! Tracing/logging initialization shared by all binaries.
//!
//! Honors `RUST_LOG` when set; otherwise defaults to `info` for the workspace
//! crates and `warn` for third-party dependencies. Safe to call once per
//! process; repeated calls are no-ops.

use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber.
///
/// Returns `Ok(())` on first init and silently ignores re-initialization so
/// test harnesses that call it multiple times do not panic.
pub fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        // info-level for our own crates, warn for noisy dependencies.
        EnvFilter::new("info,guard_core=debug,guardd=debug,guardctl=debug")
    });
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_logging_is_idempotent() {
        // Calling twice must not panic.
        init_logging();
        init_logging();
    }
}
