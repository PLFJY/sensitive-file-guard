//! Synthetic browser-profile and SSH fixtures for integration tests.
//!
//! Every fixture contains only harmless marker strings — never real secrets.
//! Tests assert on these markers both to confirm synthetic data is in use and
//! to assert that marker content never leaks into audit logs.
//!
//! No fixture or test in this crate performs any network I/O.

pub mod chromium;
pub mod firefox;
pub mod markers;
pub mod ssh;
pub mod util;

pub use chromium::ChromiumProfile;
pub use firefox::FirefoxProfile;
pub use ssh::SshFixture;
