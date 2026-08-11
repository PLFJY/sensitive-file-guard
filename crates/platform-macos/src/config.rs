use std::collections::HashSet;
use std::path::{Path, PathBuf};

use guard_platform::config::PolicyConfig;
use serde::{Deserialize, Serialize};

use crate::browser_trust::MacBrowserEnrollment;

pub const MAC_CONFIG_VERSION: u32 = 1;
pub const SYSTEM_CONFIG_PATH: &str =
    "/Library/Application Support/Sensitive Data Firewall/config.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacBackendConfig {
    pub version: u32,
    pub common_policy: PolicyConfig,
    pub browser_trust: Vec<MacBrowserEnrollment>,
}

impl MacBackendConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == MAC_CONFIG_VERSION,
            "unsupported macOS config version"
        );
        self.common_policy.validate()?;
        let mut ids = HashSet::new();
        for browser in &self.browser_trust {
            anyhow::ensure!(
                ids.insert(browser.browser_id.0.as_str()),
                "duplicate macOS browser trust enrollment"
            );
            let common = self
                .common_policy
                .browsers
                .iter()
                .find(|candidate| candidate.id == browser.browser_id.0)
                .ok_or_else(|| anyhow::anyhow!("macOS browser trust has no common policy entry"))?;
            anyhow::ensure!(
                common.family == browser.family
                    && common.profile_root == browser.profile_root
                    && common.owner_uid == Some(browser.owner_uid),
                "macOS browser trust facts do not match common policy metadata"
            );
            let common_executables = common
                .exe_paths
                .iter()
                .map(PathBuf::as_path)
                .collect::<HashSet<_>>();
            let trusted_executables = browser
                .executables
                .iter()
                .map(|executable| executable.path())
                .collect::<HashSet<_>>();
            anyhow::ensure!(
                common_executables == trusted_executables,
                "macOS browser executable metadata does not match common policy"
            );
            anyhow::ensure!(
                !browser.executables.is_empty(),
                "macOS browser trust must include an executable"
            );
        }
        for common in &self.common_policy.browsers {
            anyhow::ensure!(
                common.owner_uid.is_some(),
                "macOS browser enrollment requires an explicit owner UID"
            );
            anyhow::ensure!(
                self.browser_trust
                    .iter()
                    .any(|browser| browser.browser_id.0 == common.id),
                "common browser policy has no macOS trust enrollment"
            );
        }
        Ok(())
    }

    pub fn authoritative_path() -> &'static Path {
        Path::new(SYSTEM_CONFIG_PATH)
    }

    pub fn to_metadata_review(&self) -> MacConfigReview {
        MacConfigReview {
            version: self.version,
            authoritative_path: PathBuf::from(SYSTEM_CONFIG_PATH),
            browsers: self
                .browser_trust
                .iter()
                .map(|browser| MacBrowserConfigReview {
                    id: browser.browser_id.0.clone(),
                    profile_root: browser.profile_root.clone(),
                    owner_uid: browser.owner_uid,
                    app_bundle: browser.app_bundle.clone(),
                    executable_paths: browser
                        .executables
                        .iter()
                        .map(|executable| executable.path().to_path_buf())
                        .collect(),
                })
                .collect(),
            ssh_key_paths: self.common_policy.ssh_keys.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacConfigReview {
    pub version: u32,
    pub authoritative_path: PathBuf,
    pub browsers: Vec<MacBrowserConfigReview>,
    pub ssh_key_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacBrowserConfigReview {
    pub id: String,
    pub profile_root: PathBuf,
    pub owner_uid: u32,
    pub app_bundle: Option<PathBuf>,
    pub executable_paths: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_trust::{BrowserExecutableRole, MacExecutableEnrollment};
    use guard_core::resource::{BrowserFamily, BrowserId};
    use guard_platform::config::BrowserEnrollmentConfig;

    fn config() -> MacBackendConfig {
        let profile = PathBuf::from("/Users/test/Library/Application Support/Google/Chrome");
        let executable =
            PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        MacBackendConfig {
            version: MAC_CONFIG_VERSION,
            common_policy: PolicyConfig {
                browsers: vec![BrowserEnrollmentConfig {
                    id: "chrome".to_owned(),
                    family: BrowserFamily::Chromium,
                    profile_root: profile.clone(),
                    owner_uid: Some(501),
                    exe_paths: vec![executable.clone()],
                }],
                enrolled_exes: vec![],
                ssh_keys: vec![],
            },
            browser_trust: vec![MacBrowserEnrollment {
                browser_id: BrowserId("chrome".to_owned()),
                family: BrowserFamily::Chromium,
                profile_root: profile,
                owner_uid: 501,
                app_bundle: Some(PathBuf::from("/Applications/Google Chrome.app")),
                executables: vec![MacExecutableEnrollment::Signed {
                    role: BrowserExecutableRole::Main,
                    path: executable,
                    bundle_suffix: None,
                    team_id: "EQHXZ8M8AV".to_owned(),
                    signing_id: "com.google.Chrome".to_owned(),
                }],
            }],
        }
    }

    #[test]
    fn mac_config_round_trips_without_linux_backend_mode() {
        let config = config();
        config.validate().unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("enforcement_mode"));
        assert_eq!(
            serde_json::from_str::<MacBackendConfig>(&json).unwrap(),
            config
        );
    }

    #[test]
    fn mismatched_owner_or_profile_is_rejected() {
        let mut config = config();
        config.browser_trust[0].owner_uid = 502;
        assert!(config.validate().is_err());
    }

    #[test]
    fn review_dto_omits_hashes_and_raw_signing_or_audit_blobs() {
        let review = serde_json::to_string(&config().to_metadata_review()).unwrap();
        assert!(!review.contains("sha256"));
        assert!(!review.contains("cdhash"));
        assert!(!review.contains("audit"));
    }
}
