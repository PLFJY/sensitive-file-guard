//! Phase 01 smoke test: verifies the workspace builds, the fixture crate is
//! reachable from an integration test, and fixtures are created/cleaned up.
//!
//! Uses only synthetic data. No real browser/SSH secrets are accessed.

use guard_test_fixtures::markers;
use guard_test_fixtures::{ChromiumProfile, FirefoxProfile, SshFixture};

#[test]
fn workspace_smoke_with_all_fixtures() {
    let chromium = ChromiumProfile::create("Default").expect("chromium fixture");
    let firefox = FirefoxProfile::create("test-profile").expect("firefox fixture");
    let ssh = SshFixture::create().expect("ssh fixture");

    assert!(chromium.cookies.is_file());
    assert!(firefox.cookies_sqlite.is_file());
    assert!(ssh.private_key.is_file());

    let cookie = std::fs::read(&chromium.cookies).unwrap();
    assert_eq!(cookie, markers::COOKIE_MARKER.as_bytes());

    let ff_cookie = std::fs::read(&firefox.cookies_sqlite).unwrap();
    assert_eq!(ff_cookie, markers::FIREFOX_COOKIE_MARKER.as_bytes());
}
