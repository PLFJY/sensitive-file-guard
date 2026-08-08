//! Linux capability detection.
//!
//! fanotify permission-event enforcement (`FAN_CLASS_CONTENT`) requires
//! `CAP_SYS_ADMIN`. We detect it by parsing `/proc/self/status` so the daemon
//! can fail fast with a precise message instead of silently falling back to a
//! non-enforcing notification-only mode.

use std::fs;
use std::io;

/// Capability number for `CAP_SYS_ADMIN` (Linux UAPI).
pub const CAP_SYS_ADMIN: u32 = 21;

/// Parse the `CapEff:` line from `/proc/self/status` text into a bitmask.
///
/// Pure function for unit testing.
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:\t") {
            return u64::from_str_radix(rest.trim(), 16).ok();
        }
    }
    None
}

/// Read this process's effective capability set.
pub fn effective_caps() -> io::Result<u64> {
    let status = fs::read_to_string("/proc/self/status")?;
    parse_cap_eff(&status).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "CapEff missing"))
}

/// Returns true if the current process has `CAP_SYS_ADMIN` in its effective set.
pub fn has_cap_sys_admin() -> bool {
    effective_caps()
        .map(|c| c & (1u64 << CAP_SYS_ADMIN) != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cap_eff_line() {
        let sample = "Name:\tguardd\nUmask:\t0022\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t0000000000400000\nCapBnd:\t000001ffffffffff\n";
        // 0x400000 == 1 << 22 (cap_sys_ptrace), not sys_admin (21)
        let caps = parse_cap_eff(sample).expect("present");
        assert_eq!(caps, 0x400000);
        assert!(!has_sys_admin(caps));
    }

    #[test]
    fn detects_sys_admin_bit() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert!(has_sys_admin(caps));
    }

    #[test]
    fn missing_line_is_none() {
        assert!(parse_cap_eff("Name:\tfoo\n").is_none());
    }

    fn has_sys_admin(caps: u64) -> bool {
        caps & (1u64 << CAP_SYS_ADMIN) != 0
    }
}
