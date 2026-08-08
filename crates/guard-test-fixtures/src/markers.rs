//! Harmless marker strings embedded in synthetic fixtures.
//!
//! These exist so tests can:
//!  1. prove they are operating on synthetic data, never the developer's real
//!     secrets;
//!  2. assert that marker content never leaks into audit logs (audit events
//!     must never contain secret contents).
//!
//! All markers are plain ASCII and intentionally self-describing.

pub const COOKIE_MARKER: &str = "GUARD_SYNTHETIC_COOKIE_FIXTURE";
pub const SESSION_MARKER: &str = "GUARD_SYNTHETIC_SESSION_FIXTURE";
pub const LOGIN_MARKER: &str = "GUARD_SYNTHETIC_LOGIN_FIXTURE";
pub const KEY_MATERIAL_MARKER: &str = "GUARD_SYNTHETIC_KEYMATERIAL_FIXTURE";
pub const WEB_STORAGE_MARKER: &str = "GUARD_SYNTHETIC_WEBSTORAGE_FIXTURE";
pub const SAVED_CRED_MARKER: &str = "GUARD_SYNTHETIC_SAVEDCRED_FIXTURE";

pub const FIREFOX_COOKIE_MARKER: &str = "GUARD_SYNTHETIC_FIREFOX_COOKIE_FIXTURE";
pub const FIREFOX_LOGIN_MARKER: &str = "GUARD_SYNTHETIC_FIREFOX_LOGIN_FIXTURE";
pub const FIREFOX_KEY_MARKER: &str = "GUARD_SYNTHETIC_FIREFOX_KEY4_FIXTURE";

pub const SSH_PRIVATE_KEY_MARKER: &str = "GUARD_SYNTHETIC_SSH_PRIVATEKEY_FIXTURE";
pub const SSH_PUBLIC_KEY_MARKER: &str = "GUARD_SYNTHETIC_SSH_PUBLICKEY_FIXTURE";

/// Concatenation of all markers, useful for a single "no secret content leaked
/// into this string" sweep in audit-log assertions.
pub const ALL_MARKERS: &[&str] = &[
    COOKIE_MARKER,
    SESSION_MARKER,
    LOGIN_MARKER,
    KEY_MATERIAL_MARKER,
    WEB_STORAGE_MARKER,
    SAVED_CRED_MARKER,
    FIREFOX_COOKIE_MARKER,
    FIREFOX_LOGIN_MARKER,
    FIREFOX_KEY_MARKER,
    SSH_PRIVATE_KEY_MARKER,
    SSH_PUBLIC_KEY_MARKER,
];

/// Returns true if `haystack` contains any synthetic fixture marker.
///
/// Intended for audit-log redaction tests: an audit line must never contain
/// fixture marker bytes (which stand in for real secret bytes).
pub fn contains_any_marker(haystack: &str) -> bool {
    ALL_MARKERS.iter().any(|m| haystack.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_detection_works() {
        assert!(contains_any_marker(COOKIE_MARKER));
        assert!(contains_any_marker(&format!(
            "prefix {SSH_PRIVATE_KEY_MARKER} suffix"
        )));
        assert!(!contains_any_marker("ordinary audit line with no secrets"));
    }
}
