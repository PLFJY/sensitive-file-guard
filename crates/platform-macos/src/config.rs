use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use guard_platform::config::PolicyConfig;
use serde::{Deserialize, Serialize};

use crate::browser_trust::MacBrowserEnrollment;
use crate::code_signature::CodeSignatureInspector;
use crate::identity::MacProcessFacts;
use guard_core::resource::ProtectedResourceKind;

pub const MAC_CONFIG_VERSION: u32 = 1;
pub const SYSTEM_CONFIG_PATH: &str =
    "/Library/Application Support/Sensitive Data Firewall/config.json";
static NEXT_TEMP_CONFIG: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacSystemProcessRule {
    pub path: PathBuf,
    pub team_id: Option<String>,
    pub signing_id: String,
    #[serde(default)]
    pub platform_binary: bool,
    pub owner_uid: u32,
    #[serde(default)]
    pub allow_kinds: Vec<ProtectedResourceKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacTrustedToolRule {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub owner_uid: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacAllowlistConfig {
    #[serde(default)]
    pub system_processes: Vec<MacSystemProcessRule>,
    #[serde(default)]
    pub trusted_tools: Vec<MacTrustedToolRule>,
}

impl MacAllowlistConfig {
    pub fn with_builtin_system_rules(mut self) -> Self {
        let path = PathBuf::from(
            "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
        );
        if !self.system_processes.iter().any(|rule| rule.path == path) {
            self.system_processes.push(MacSystemProcessRule {
                path,
                team_id: None,
                signing_id: "com.apple.mdworker_shared".into(),
                platform_binary: true,
                owner_uid: 0,
                allow_kinds: vec![ProtectedResourceKind::History],
            });
        }
        self
    }

    pub fn system_rule(
        &self,
        process: &MacProcessFacts,
        kind: ProtectedResourceKind,
    ) -> Option<&MacSystemProcessRule> {
        self.system_processes.iter().find(|rule| {
            rule.path == process.executable.path
                && rule.owner_uid == process.executable.owner_uid
                && rule.platform_binary == process.code.platform_binary
                && process.code.valid
                && process.code.team_id == rule.team_id
                && process.code.signing_id.as_deref() == Some(rule.signing_id.as_str())
                && rule.allow_kinds.contains(&kind)
        })
    }

    pub fn trusted_tool_matches(&self, process: &MacProcessFacts) -> bool {
        self.trusted_tools.iter().any(|rule| {
            rule.path == process.executable.path
                && rule.dev == process.executable.dev
                && rule.ino == process.executable.ino
                && rule.owner_uid == process.executable.owner_uid
                && process.code.valid
                && process.code.signing_id.is_some()
                && rule.team_id.as_deref() == process.code.team_id.as_deref()
                && rule.signing_id.as_deref() == process.code.signing_id.as_deref()
        })
    }
}

pub fn enroll_trusted_tool(path: &Path, owner_uid: u32) -> anyhow::Result<MacTrustedToolRule> {
    let canonical = std::fs::canonicalize(path)?;
    let metadata = std::fs::metadata(&canonical)?;
    anyhow::ensure!(
        metadata.is_file() && (metadata.uid() == 0 || metadata.uid() == owner_uid),
        "trusted tool must be root-owned or owned by the current user"
    );
    let signature = crate::code_signature::NativeCodeSignatureInspector.inspect(&canonical)?;
    anyhow::ensure!(signature.valid, "trusted tool has no valid code signature");
    anyhow::ensure!(
        signature.signing_id.is_some(),
        "trusted tool has no stable signing identifier"
    );
    Ok(MacTrustedToolRule {
        path: canonical,
        dev: metadata.dev(),
        ino: metadata.ino(),
        team_id: signature.team_id,
        signing_id: signature.signing_id,
        owner_uid,
    })
}

#[cfg(test)]
mod allowlist_tests {
    use super::*;

    fn process(path: PathBuf, _kind: ProtectedResourceKind) -> MacProcessFacts {
        MacProcessFacts {
            key: crate::identity::AuditProcessKey {
                pid: 7,
                pidversion: 1,
            },
            uid: 501,
            gid: 20,
            start_time_us: 10,
            executable: crate::identity::ExecutableSnapshot {
                path,
                dev: 3,
                ino: 4,
                owner_uid: 0,
                mode: 0o100755,
                size: 1,
                mtime_ns: 1,
                ctime_ns: 1,
            },
            code: crate::identity::MacCodeIdentity {
                valid: true,
                platform_binary: true,
                flags: 0,
                team_id: None,
                signing_id: Some("com.apple.mdworker_shared".into()),
                cdhash: [0; 20],
            },
            parent: None,
            responsible: None,
        }
    }

    #[test]
    fn builtin_spotlight_rule_is_history_only_and_signature_pinned() {
        let path = PathBuf::from("/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared");
        let config = MacAllowlistConfig::default().with_builtin_system_rules();
        let process = process(path, ProtectedResourceKind::History);
        assert!(config
            .system_rule(&process, ProtectedResourceKind::History)
            .is_some());
        assert!(config
            .system_rule(&process, ProtectedResourceKind::CookieStore)
            .is_none());
    }

    #[test]
    fn builtin_rule_rejects_same_name_with_wrong_path_or_identity() {
        let config = MacAllowlistConfig::default().with_builtin_system_rules();
        let mut process = process(
            PathBuf::from("/tmp/mdworker_shared"),
            ProtectedResourceKind::History,
        );
        assert!(config
            .system_rule(&process, ProtectedResourceKind::History)
            .is_none());
        process.executable.path = PathBuf::from("/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared");
        process.code.signing_id = Some("com.example.fake".into());
        assert!(config
            .system_rule(&process, ProtectedResourceKind::History)
            .is_none());
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacBackendConfig {
    pub version: u32,
    #[serde(default)]
    pub policy_enabled: bool,
    pub common_policy: PolicyConfig,
    pub browser_trust: Vec<MacBrowserEnrollment>,
    #[serde(default)]
    pub mac_allowlist: MacAllowlistConfig,
}

impl MacBackendConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.version == MAC_CONFIG_VERSION,
            "unsupported macOS config version"
        );
        self.common_policy.validate()?;
        for rule in &self.mac_allowlist.system_processes {
            anyhow::ensure!(
                rule.path.is_absolute(),
                "macOS system allowlist path must be absolute"
            );
            if let Some(team_id) = &rule.team_id {
                anyhow::ensure!(
                    !team_id.trim().is_empty(),
                    "macOS system allowlist Team ID is empty"
                );
            }
            anyhow::ensure!(
                !rule.signing_id.trim().is_empty(),
                "macOS system allowlist signing ID is required"
            );
            anyhow::ensure!(
                !rule.allow_kinds.is_empty(),
                "macOS system allowlist must name resource kinds"
            );
        }
        for rule in &self.mac_allowlist.trusted_tools {
            anyhow::ensure!(
                rule.path.is_absolute(),
                "macOS trusted tool path must be absolute"
            );
            anyhow::ensure!(
                rule.dev != 0 && rule.ino != 0,
                "macOS trusted tool file identity is required"
            );
            let current = std::fs::metadata(&rule.path)?;
            anyhow::ensure!(
                current.dev() == rule.dev && current.ino() == rule.ino,
                "macOS trusted tool changed and requires reenrollment: {}",
                rule.path.display()
            );
        }
        let mut ssh_paths = HashSet::new();
        for key in &self.common_policy.ssh_keys {
            anyhow::ensure!(
                guard_ssh::is_private_key_candidate(key),
                "SSH enrollment rejects public-key and reserved non-private-key names: {}",
                key.display()
            );
            anyhow::ensure!(ssh_paths.insert(key), "duplicate macOS SSH key enrollment");
        }
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
        for (index, browser) in self.browser_trust.iter().enumerate() {
            for other in self.browser_trust.iter().skip(index + 1) {
                anyhow::ensure!(
                    !browser.profile_root.starts_with(&other.profile_root)
                        && !other.profile_root.starts_with(&browser.profile_root),
                    "macOS browser profile roots must not overlap"
                );
            }
        }
        Ok(())
    }

    pub fn with_builtin_mac_allowlist(mut self) -> Self {
        self.mac_allowlist = self.mac_allowlist.with_builtin_system_rules();
        self
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
        for browser in &self.browser_trust {
            let canonical = std::fs::canonicalize(&browser.profile_root)?;
            anyhow::ensure!(
                canonical == browser.profile_root,
                "browser profile enrollment must use a canonical path"
            );
            let metadata = std::fs::metadata(&canonical)?;
            anyhow::ensure!(
                metadata.is_dir() && metadata.uid() == peer_uid,
                "browser profile enrollment must be an authenticated-peer-owned directory"
            );
        }
        crate::browser_trust::MacBrowserTrustStore::load_and_revalidate(
            self.browser_trust.clone(),
        )?;
        for tool in &self.mac_allowlist.trusted_tools {
            let canonical = std::fs::canonicalize(&tool.path)?;
            anyhow::ensure!(
                canonical == tool.path,
                "macOS trusted tool path must be a canonical path"
            );
            let metadata = std::fs::metadata(&canonical)?;
            anyhow::ensure!(
                metadata.is_file() && (metadata.uid() == 0 || metadata.uid() == peer_uid),
                "macOS trusted tool must be root-owned or authenticated-peer-owned"
            );
        }
        for executable in &self.common_policy.enrolled_exes {
            let canonical = std::fs::canonicalize(executable)?;
            anyhow::ensure!(
                canonical == *executable,
                "executable enrollment must use a canonical path"
            );
            let metadata = std::fs::metadata(&canonical)?;
            let owner = metadata.uid();
            anyhow::ensure!(
                metadata.is_file() && (owner == 0 || owner == peer_uid),
                "executable enrollment must be root-owned or authenticated-peer-owned"
            );
        }
        for key in &self.common_policy.ssh_keys {
            let resource = guard_ssh::enroll_key(key)?;
            let canonical = resource.path;
            anyhow::ensure!(
                canonical == *key,
                "SSH key enrollment must use a canonical path"
            );
            anyhow::ensure!(
                resource.owner_uid == peer_uid,
                "SSH key enrollment must be an authenticated-peer-owned file"
            );
        }
        Ok(())
    }

    /// Build a peer-scoped configuration update for one SSH key. Enrollment
    /// canonicalizes/stats the file and applies shared name rules without
    /// opening or parsing private-key contents.
    pub fn with_ssh_key_for_peer(
        current: Option<&Self>,
        path: &Path,
        peer_uid: u32,
    ) -> anyhow::Result<(Self, guard_core::ProtectedResource)> {
        let resource = guard_ssh::enroll_key(path)?;
        anyhow::ensure!(
            resource.owner_uid == peer_uid,
            "only the authenticated key owner may enroll this SSH key"
        );
        let mut config = current.cloned().unwrap_or_else(|| Self {
            version: MAC_CONFIG_VERSION,
            policy_enabled: true,
            common_policy: PolicyConfig {
                browsers: Vec::new(),
                enrolled_exes: Vec::new(),
                ssh_keys: Vec::new(),
            },
            browser_trust: Vec::new(),
            mac_allowlist: MacAllowlistConfig::default(),
        });
        if let Some(current) = current {
            current.validate_for_peer(peer_uid)?;
        }
        if !config.common_policy.ssh_keys.contains(&resource.path) {
            config.common_policy.ssh_keys.push(resource.path.clone());
            config.common_policy.ssh_keys.sort();
        }
        config.validate_for_peer(peer_uid)?;
        Ok((config, resource))
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
            policy_enabled: Some(self.policy_enabled),
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
                        guard_core::resource::BrowserFamily::Safari => "safari",
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
            mac_system_processes: self
                .mac_allowlist
                .system_processes
                .iter()
                .map(|rule| guard_ipc::MacSystemProcessInfo {
                    path: rule.path.to_string_lossy().into_owned(),
                    signing_id: rule.signing_id.clone(),
                    allow_kinds: rule
                        .allow_kinds
                        .iter()
                        .map(|kind| kind.kind_code().to_owned())
                        .collect(),
                })
                .collect(),
            mac_trusted_tools: self
                .mac_allowlist
                .trusted_tools
                .iter()
                .map(|rule| guard_ipc::MacTrustedToolInfo {
                    path: rule.path.to_string_lossy().into_owned(),
                    team_id: rule.team_id.clone(),
                    signing_id: rule.signing_id.clone(),
                    dev: rule.dev,
                    ino: rule.ino,
                })
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
            policy_enabled: true,
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
            mac_allowlist: MacAllowlistConfig::default(),
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
    fn overlapping_browser_profile_roots_are_rejected() {
        let mut config = config();
        let mut nested = config.browser_trust[0].clone();
        nested.browser_id = BrowserId("nested".into());
        nested.profile_root = nested.profile_root.join("Default");
        let mut common = config.common_policy.browsers[0].clone();
        common.id = "nested".into();
        common.profile_root = nested.profile_root.clone();
        config.browser_trust.push(nested);
        config.common_policy.browsers.push(common);
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

    #[test]
    fn peer_validation_accepts_only_owned_synthetic_browser_scope() {
        // SAFETY: geteuid has no pointer arguments and reads only the test
        // process credential.
        let uid = unsafe { libc::geteuid() };
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("profile");
        std::fs::create_dir(&profile).unwrap();
        let executable = root.path().join("custom-browser");
        std::fs::write(&executable, b"synthetic executable bytes").unwrap();
        let profile = std::fs::canonicalize(profile).unwrap();
        let executable = std::fs::canonicalize(executable).unwrap();
        let enrollment = crate::browser_trust::enroll_custom_executable(&executable).unwrap();
        let config = MacBackendConfig {
            version: MAC_CONFIG_VERSION,
            policy_enabled: true,
            common_policy: PolicyConfig {
                browsers: vec![BrowserEnrollmentConfig {
                    id: "custom".into(),
                    family: BrowserFamily::Chromium,
                    profile_root: profile.clone(),
                    owner_uid: Some(uid),
                    exe_paths: vec![executable.clone()],
                }],
                enrolled_exes: Vec::new(),
                ssh_keys: Vec::new(),
            },
            browser_trust: vec![MacBrowserEnrollment {
                browser_id: BrowserId("custom".into()),
                family: BrowserFamily::Chromium,
                profile_root: profile,
                owner_uid: uid,
                app_bundle: None,
                executables: vec![enrollment],
            }],
            mac_allowlist: MacAllowlistConfig::default(),
        };
        config.validate_for_peer(uid).unwrap();
        assert!(config.validate_for_peer(uid.saturating_add(1)).is_err());
    }

    #[test]
    fn ssh_enrollment_uses_owner_and_name_metadata_without_reading_key() {
        // SAFETY: geteuid has no pointer arguments and reads only the test
        // process credential.
        let uid = unsafe { libc::geteuid() };
        let root = tempfile::tempdir().unwrap();
        let key = root.path().join("id_ed25519");
        std::fs::write(&key, b"ephemeral synthetic key bytes").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
        let (config, resource) = MacBackendConfig::with_ssh_key_for_peer(None, &key, uid).unwrap();
        assert!(config.policy_enabled);
        assert_eq!(config.common_policy.ssh_keys, vec![resource.path]);
        assert!(config.browser_trust.is_empty());
        assert_eq!(config.to_ipc_metadata_for_uid(uid).ssh_keys.len(), 1);

        let public = root.path().join("id_ed25519.pub");
        std::fs::write(&public, b"synthetic public key").unwrap();
        assert!(MacBackendConfig::with_ssh_key_for_peer(Some(&config), &public, uid).is_err());
        let reserved = root.path().join("known_hosts");
        std::fs::write(&reserved, b"synthetic host metadata").unwrap();
        assert!(MacBackendConfig::with_ssh_key_for_peer(Some(&config), &reserved, uid).is_err());
    }
}
