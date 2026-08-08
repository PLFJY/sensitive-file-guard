//! Browser profile discovery and protected-resource classification.
//!
//! Phase 05: concrete Chromium-family + Firefox discovery and a protected
//! resource registry. Discovery is driven by explicit `BrowserId`/family
//! enrollment from config — no permanent trust is granted merely because a
//! path is called "Chrome".

pub mod chromium;
pub mod firefox;
pub mod registry;

pub use chromium::discover as discover_chromium;
pub use firefox::discover as discover_firefox;
pub use registry::{ProtectedResourceRegistry, TreeRoot};

use guard_core::resource::BrowserId;

/// A custom (non-standard-location) browser profile enrollment requested by
/// the user via config. `family` selects the pattern set; `root` is either a
/// Chromium `user_data_dir` or a Firefox profiles root / single profile dir.
#[derive(Debug, Clone)]
pub struct CustomProfile {
    pub browser: BrowserId,
    pub family: guard_core::resource::BrowserFamily,
    pub root: std::path::PathBuf,
    pub owner_uid: u32,
}

impl CustomProfile {
    /// Discover resources for this custom enrollment and populate `registry`.
    pub fn enroll_into(&self, registry: &mut ProtectedResourceRegistry) -> std::io::Result<()> {
        use guard_core::resource::BrowserFamily;
        let (files, trees) = match self.family {
            BrowserFamily::Chromium => {
                discover_chromium(&self.browser, &self.root, self.owner_uid)?
            }
            BrowserFamily::Firefox | BrowserFamily::Zen => {
                discover_firefox(&self.browser, &self.root, self.owner_uid)?
            }
        };
        for f in files {
            registry.enroll_file(f);
        }
        for t in trees {
            registry.enroll_tree(t);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::resource::BrowserFamily;
    use guard_test_fixtures::chromium::ChromiumProfile;
    use guard_test_fixtures::firefox::FirefoxProfile;

    #[test]
    fn custom_chromium_profile_enrollment_works() {
        let p = ChromiumProfile::create("Default").expect("create fixture");
        let mut reg = ProtectedResourceRegistry::new();
        let custom = CustomProfile {
            browser: BrowserId("chrome".into()),
            family: BrowserFamily::Chromium,
            root: p.user_data_dir.clone(),
            owner_uid: 1000,
        };
        custom.enroll_into(&mut reg).expect("enroll");
        assert!(reg.file_count() >= 6);
        assert!(!reg.trees().is_empty());
        // A protected file classifies.
        assert!(reg.classify(&p.cookies).is_some());
        // A tree descendant classifies.
        let descendant = p.local_storage_dir.join("https_example.com_0.localstorage");
        assert!(reg.classify(&descendant).is_some());
    }

    #[test]
    fn custom_firefox_profile_enrollment_works() {
        let p = FirefoxProfile::create("test-profile").expect("create fixture");
        let mut reg = ProtectedResourceRegistry::new();
        let custom = CustomProfile {
            browser: BrowserId("firefox".into()),
            family: BrowserFamily::Firefox,
            root: p.profile_dir.clone(),
            owner_uid: 1000,
        };
        custom.enroll_into(&mut reg).expect("enroll");
        assert!(reg.classify(&p.cookies_sqlite).is_some());
        assert!(reg.classify(&p.key4_db).is_some());
    }
}
