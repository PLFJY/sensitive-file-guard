use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use guard_platform::config::PolicyConfig;
use serde::{Deserialize, Serialize};

use crate::browser_trust::MacBrowserEnrollment;

pub const MAC_CONFIG_VERSION: u32 = 1;
pub const SYSTEM_CONFIG_PATH: &str =
    "/Library/Application Support/Sensitive Data Firewall/config.json";
static NEXT_TEMP_CONFIG: AtomicU64 = AtomicU64::new(0);

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

    pub fn validate_for_peer(&self, peer_uid: u32) -> anyhow::Result<()> {
        self.validate()?;
        anyhow::ensure!(
            self.common_policy
                .browsers
                .iter()
                .all(|browser| browser.owner_uid == Some(peer_uid)),
            "macOS configuration may change only the authenticated peer's browser scope"
        );
        for key in &self.common_policy.ssh_keys {
            let canonical = std::fs::canonicalize(key)?;
            anyhow::ensure!(
                canonical == *key,
                "SSH key enrollment must use a canonical path"
            );
            let metadata = std::fs::metadata(&canonical)?;
            anyhow::ensure!(
                metadata.is_file() && metadata.uid() == peer_uid,
                "SSH key enrollment must be an authenticated-peer-owned file"
            );
        }
        Ok(())
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

    pub fn to_ipc_metadata(&self) -> guard_ipc::ConfigurationInfo {
        guard_ipc::ConfigurationInfo {
            enforcement_mode: None,
            browsers: self
                .common_policy
                .browsers
                .iter()
                .map(|browser| guard_ipc::ConfiguredBrowserInfo {
                    id: browser.id.clone(),
                    family: match browser.family {
                        guard_core::resource::BrowserFamily::Chromium => "chromium",
                        guard_core::resource::BrowserFamily::Firefox => "firefox",
                        guard_core::resource::BrowserFamily::Zen => "zen",
                    }
                    .into(),
                    profile_root: browser.profile_root.to_string_lossy().into_owned(),
                    owner_uid: browser.owner_uid,
                    exe_paths: browser
                        .exe_paths
                        .iter()
                        .map(|path| path.to_string_lossy().into_owned())
                        .collect(),
                })
                .collect(),
            enrolled_exes: self
                .common_policy
                .enrolled_exes
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            ssh_keys: self
                .common_policy
                .ssh_keys
                .iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
        }
    }

    /// Return only configuration metadata belonging to the authenticated XPC
    /// peer. Paths without an explicit policy owner are included only when the
    /// filesystem owner is either root (shared system executable) or the peer.
    pub fn to_ipc_metadata_for_uid(&self, uid: u32) -> guard_ipc::ConfigurationInfo {
        let mut metadata = self.to_ipc_metadata();
        metadata
            .browsers
            .retain(|browser| browser.owner_uid == Some(uid));
        metadata.enrolled_exes.retain(|path| {
            std::fs::metadata(path).is_ok_and(|file| {
                let owner = file.uid();
                owner == 0 || owner == uid
            })
        });
        metadata
            .ssh_keys
            .retain(|path| std::fs::metadata(path).is_ok_and(|file| file.uid() == uid));
        metadata
    }

    pub fn load_authoritative() -> anyhow::Result<Self> {
        let bytes = std::fs::read(Self::authoritative_path())?;
        let config: Self = serde_json::from_slice(&bytes)?;
        config.validate()?;
        Ok(config)
    }

    pub fn write_authoritative(&self) -> anyhow::Result<()> {
        // SAFETY: geteuid has no pointer arguments and only reads the current
        // process credential at this privileged platform boundary.
        anyhow::ensure!(
            unsafe { libc::geteuid() } == 0,
            "authoritative config write requires root"
        );
        persist(self, Self::authoritative_path(), true)
    }
}

fn persist(
    config: &MacBackendConfig,
    path: &Path,
    require_root_parent: bool,
) -> anyhow::Result<()> {
    config.validate()?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("macOS config path has no parent"))?;
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "macOS config parent must be a real directory"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(parent)?;
        }
        Err(error) => return Err(error.into()),
    }
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    let metadata = std::fs::metadata(parent)?;
    if require_root_parent {
        anyhow::ensure!(
            metadata.uid() == 0,
            "macOS config directory is not root-owned"
        );
    }
    anyhow::ensure!(
        metadata.mode() & 0o077 == 0,
        "macOS config directory is too permissive"
    );

    let sequence = NEXT_TEMP_CONFIG.fetch_add(1, Ordering::Relaxed);
    let temp = parent.join(format!(
        ".config.json.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let result = (|| -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec_pretty(config)?;
        bytes.push(b'\n');
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&temp, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
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

    #[test]
    fn synthetic_authoritative_write_is_atomic_and_mode_0600() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("config/config.json");
        persist(&config(), &path, false).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        let loaded: MacBackendConfig =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(loaded, config());
        assert!(std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")));
    }

    #[test]
    fn peer_scope_rejects_another_users_browser() {
        assert!(config().validate_for_peer(502).is_err());
    }

    #[test]
    fn ipc_metadata_is_scoped_to_authenticated_peer() {
        let mut config = config();
        let mut other = config.common_policy.browsers[0].clone();
        other.id = "other-user".to_owned();
        other.owner_uid = Some(502);
        config.common_policy.browsers.push(other);

        let metadata = config.to_ipc_metadata_for_uid(501);
        assert_eq!(metadata.browsers.len(), 1);
        assert_eq!(metadata.browsers[0].owner_uid, Some(501));
    }
}
