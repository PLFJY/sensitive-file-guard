use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use guard_core::identity::{ProcessIdentity, ProcessStableId, TrustTier};
use guard_core::resource::{BrowserFamily, BrowserId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::identity::MacProcessGraph;
use crate::identity::{ExecutableSnapshot, MacProcessFacts};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserExecutableRole {
    Main,
    Helper,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "trust_kind", rename_all = "snake_case")]
pub enum MacExecutableEnrollment {
    Signed {
        role: BrowserExecutableRole,
        path: PathBuf,
        #[serde(default)]
        bundle_suffix: Option<PathBuf>,
        team_id: String,
        signing_id: String,
    },
    ExplicitHash {
        path: PathBuf,
        dev: u64,
        ino: u64,
        size: u64,
        mtime_ns: i64,
        ctime_ns: i64,
        sha256: [u8; 32],
    },
}

impl MacExecutableEnrollment {
    pub fn path(&self) -> &Path {
        match self {
            Self::Signed { path, .. } | Self::ExplicitHash { path, .. } => path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacBrowserEnrollment {
    pub browser_id: BrowserId,
    pub family: BrowserFamily,
    pub profile_root: PathBuf,
    pub owner_uid: u32,
    pub app_bundle: Option<PathBuf>,
    pub executables: Vec<MacExecutableEnrollment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserTrustDecision {
    pub browser: Option<BrowserId>,
    pub tier: TrustTier,
}

impl BrowserTrustDecision {
    fn unknown() -> Self {
        Self {
            browser: None,
            tier: TrustTier::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MacBrowserTrustStore {
    browsers: Vec<MacBrowserEnrollment>,
}

pub struct MacProcessIdentityResolver {
    graph: std::sync::Arc<std::sync::Mutex<MacProcessGraph>>,
    trust: std::sync::Arc<std::sync::RwLock<MacBrowserTrustStore>>,
}

impl MacProcessIdentityResolver {
    pub fn new(
        graph: std::sync::Arc<std::sync::Mutex<MacProcessGraph>>,
        trust: MacBrowserTrustStore,
    ) -> Self {
        Self {
            graph,
            trust: std::sync::Arc::new(std::sync::RwLock::new(trust)),
        }
    }

    pub fn new_shared(
        graph: std::sync::Arc<std::sync::Mutex<MacProcessGraph>>,
        trust: std::sync::Arc<std::sync::RwLock<MacBrowserTrustStore>>,
    ) -> Self {
        Self { graph, trust }
    }

    pub fn replace_trust(&self, trust: MacBrowserTrustStore) -> anyhow::Result<()> {
        *self
            .trust
            .write()
            .map_err(|_| anyhow::anyhow!("macOS browser trust lock is poisoned"))? = trust;
        Ok(())
    }
}

impl guard_platform::ProcessIdentityResolver for MacProcessIdentityResolver {
    fn resolve(&self, pid: u32, resource_owner_uid: u32) -> anyhow::Result<ProcessIdentity> {
        let graph = self
            .graph
            .lock()
            .map_err(|_| anyhow::anyhow!("macOS process graph lock is poisoned"))?;
        let facts = graph
            .current(pid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("current process graph entry is missing"))?;
        // A direct, fully signed browser identity does not depend on seeing
        // its pre-extension parent. Missing ancestry simply leaves descendant
        // lease matching unavailable; it never becomes permission to allow.
        let ancestors = graph
            .ancestors(facts.key, std::time::Instant::now())
            .unwrap_or_default();
        let trust = self
            .trust
            .read()
            .map_err(|_| anyhow::anyhow!("macOS browser trust lock is poisoned"))?
            .classify(&facts, resource_owner_uid);
        Ok(ProcessIdentity {
            stable: facts.stable_id(),
            uid: facts.uid,
            gid: facts.gid,
            exe_owner_uid: facts.executable.owner_uid,
            browser: trust.browser,
            trust_tier: trust.tier,
            cmdline: Vec::new(),
            ancestors,
        })
    }

    fn is_live_instance(&self, identity: &ProcessStableId) -> anyhow::Result<bool> {
        let graph = self
            .graph
            .lock()
            .map_err(|_| anyhow::anyhow!("macOS process graph lock is poisoned"))?;
        Ok(graph.is_live_instance(identity))
    }

    fn ancestors(&self, pid: u32) -> anyhow::Result<Vec<guard_core::identity::AncestorSummary>> {
        let graph = self
            .graph
            .lock()
            .map_err(|_| anyhow::anyhow!("macOS process graph lock is poisoned"))?;
        let facts = graph
            .current(pid)
            .ok_or_else(|| anyhow::anyhow!("current process graph entry is missing"))?;
        graph.ancestors(facts.key, std::time::Instant::now())
    }
}

impl MacBrowserTrustStore {
    pub fn load_and_revalidate(browsers: Vec<MacBrowserEnrollment>) -> anyhow::Result<Self> {
        for browser in &browsers {
            anyhow::ensure!(
                browser.profile_root.is_absolute(),
                "profile root must be absolute"
            );
            for executable in &browser.executables {
                anyhow::ensure!(
                    executable.path().is_absolute(),
                    "executable path must be absolute"
                );
                match executable {
                    MacExecutableEnrollment::Signed {
                        path,
                        bundle_suffix,
                        ..
                    } => {
                        let bundle = browser.app_bundle.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("signed browser enrollment requires an app bundle")
                        })?;
                        anyhow::ensure!(
                            path.starts_with(bundle),
                            "signed browser executable is outside its enrolled app bundle"
                        );
                        if let Some(suffix) = bundle_suffix {
                            anyhow::ensure!(
                                !suffix.is_absolute()
                                    && !suffix.components().any(|component| matches!(
                                        component,
                                        std::path::Component::ParentDir
                                            | std::path::Component::RootDir
                                            | std::path::Component::Prefix(_)
                                    )),
                                "signed helper suffix must remain relative to the app bundle"
                            );
                            anyhow::ensure!(
                                path.ends_with(suffix),
                                "signed helper suffix does not match its observed path"
                            );
                        }
                    }
                    MacExecutableEnrollment::ExplicitHash { .. } => {
                        anyhow::ensure!(
                            verify_explicit_hash(executable)?,
                            "custom executable changed and requires explicit reenrollment: {}",
                            executable.path().display()
                        );
                    }
                }
            }
        }
        Ok(Self { browsers })
    }

    pub fn classify(
        &self,
        process: &MacProcessFacts,
        resource_owner_uid: u32,
    ) -> BrowserTrustDecision {
        if process.uid != resource_owner_uid {
            return BrowserTrustDecision::unknown();
        }
        for browser in &self.browsers {
            if browser.owner_uid != resource_owner_uid {
                continue;
            }
            for executable in &browser.executables {
                let versioned_helper_path = matches!(
                    executable,
                    MacExecutableEnrollment::Signed {
                        role: BrowserExecutableRole::Helper,
                        bundle_suffix: Some(suffix),
                        ..
                    } if browser.app_bundle.as_ref().is_some_and(|bundle| {
                        process.executable.path.starts_with(bundle)
                            && process.executable.path.ends_with(suffix)
                    })
                );
                if executable.path() != process.executable.path && !versioned_helper_path {
                    continue;
                }
                let trusted = match executable {
                    MacExecutableEnrollment::Signed {
                        role,
                        path,
                        bundle_suffix,
                        team_id,
                        signing_id,
                    } => {
                        let bundle_ok = browser
                            .app_bundle
                            .as_ref()
                            .is_some_and(|bundle| path.starts_with(bundle));
                        let path_ok = process.executable.path == *path
                            || (*role == BrowserExecutableRole::Helper
                                && bundle_suffix.as_ref().is_some_and(|suffix| {
                                    process.executable.path.starts_with(
                                        browser.app_bundle.as_ref().expect("bundle checked"),
                                    ) && process.executable.path.ends_with(suffix)
                                }));
                        process.code.valid
                            && bundle_ok
                            && path_ok
                            && process.code.team_id.as_deref() == Some(team_id)
                            && process.code.signing_id.as_deref() == Some(signing_id)
                    }
                    MacExecutableEnrollment::ExplicitHash {
                        dev,
                        ino,
                        size,
                        mtime_ns,
                        ctime_ns,
                        ..
                    } => {
                        process.executable.dev == *dev
                            && process.executable.ino == *ino
                            && process.executable.size == *size
                            && process.executable.mtime_ns == *mtime_ns
                            && process.executable.ctime_ns == *ctime_ns
                    }
                };
                if trusted {
                    return BrowserTrustDecision {
                        browser: Some(browser.browser_id.clone()),
                        tier: match executable {
                            MacExecutableEnrollment::Signed { .. } => TrustTier::Sandbox,
                            MacExecutableEnrollment::ExplicitHash { .. } => {
                                TrustTier::EnrolledUserWritable
                            }
                        },
                    };
                }
            }
        }
        BrowserTrustDecision::unknown()
    }

    pub fn browsers(&self) -> &[MacBrowserEnrollment] {
        &self.browsers
    }
}

pub fn enroll_custom_executable(path: &Path) -> anyhow::Result<MacExecutableEnrollment> {
    let canonical = std::fs::canonicalize(path)?;
    let metadata = std::fs::metadata(&canonical)?;
    let snapshot = snapshot(&canonical, &metadata);
    Ok(MacExecutableEnrollment::ExplicitHash {
        path: canonical.clone(),
        dev: snapshot.dev,
        ino: snapshot.ino,
        size: snapshot.size,
        mtime_ns: snapshot.mtime_ns,
        ctime_ns: snapshot.ctime_ns,
        sha256: hash_file(&canonical)?,
    })
}

fn verify_explicit_hash(enrollment: &MacExecutableEnrollment) -> anyhow::Result<bool> {
    let MacExecutableEnrollment::ExplicitHash {
        path,
        dev,
        ino,
        size,
        mtime_ns,
        ctime_ns,
        sha256,
    } = enrollment
    else {
        return Ok(false);
    };
    let metadata = std::fs::metadata(path)?;
    let current = snapshot(path, &metadata);
    Ok(current.dev == *dev
        && current.ino == *ino
        && current.size == *size
        && current.mtime_ns == *mtime_ns
        && current.ctime_ns == *ctime_ns
        && hash_file(path)? == *sha256)
}

fn snapshot(path: &Path, metadata: &std::fs::Metadata) -> ExecutableSnapshot {
    use std::os::unix::fs::MetadataExt;

    ExecutableSnapshot {
        path: path.to_path_buf(),
        dev: metadata.dev(),
        ino: metadata.ino(),
        owner_uid: metadata.uid(),
        mode: metadata.mode(),
        size: metadata.size(),
        mtime_ns: metadata.mtime().saturating_mul(1_000_000_000) + metadata.mtime_nsec(),
        ctime_ns: metadata.ctime().saturating_mul(1_000_000_000) + metadata.ctime_nsec(),
    }
}

fn hash_file(path: &Path) -> anyhow::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{AuditProcessKey, MacCodeIdentity};
    use std::os::unix::fs::MetadataExt;

    fn signed_browser(
        root: &Path,
        executable: &Path,
        role: BrowserExecutableRole,
    ) -> MacBrowserEnrollment {
        MacBrowserEnrollment {
            browser_id: BrowserId("chrome".to_owned()),
            family: BrowserFamily::Chromium,
            profile_root: root.join("profile"),
            owner_uid: 501,
            app_bundle: Some(root.join("Chrome.app")),
            executables: vec![MacExecutableEnrollment::Signed {
                role,
                path: executable.to_path_buf(),
                bundle_suffix: None,
                team_id: "TEAM".to_owned(),
                signing_id: "com.example.chrome".to_owned(),
            }],
        }
    }

    fn process(path: &Path, uid: u32, team: &str, signing: &str) -> MacProcessFacts {
        let metadata = std::fs::metadata(path).unwrap();
        MacProcessFacts {
            key: AuditProcessKey {
                pid: 50,
                pidversion: 3,
            },
            uid,
            gid: 20,
            start_time_us: 100,
            executable: snapshot(path, &metadata),
            code: MacCodeIdentity {
                valid: true,
                platform_binary: false,
                flags: 1,
                team_id: Some(team.to_owned()),
                signing_id: Some(signing.to_owned()),
                cdhash: [7; 20],
            },
            parent: None,
            responsible: None,
        }
    }

    #[test]
    fn team_and_signing_id_must_match_exactly() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("Chrome.app/Contents/MacOS/Chrome");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"signed fixture").unwrap();
        let store = MacBrowserTrustStore::load_and_revalidate(vec![signed_browser(
            temp.path(),
            &executable,
            BrowserExecutableRole::Main,
        )])
        .unwrap();
        assert!(store
            .classify(
                &process(&executable, 501, "TEAM", "com.example.chrome"),
                501,
            )
            .tier
            .is_trusted());
        assert_eq!(
            store
                .classify(
                    &process(&executable, 501, "WRONG", "com.example.chrome"),
                    501,
                )
                .tier,
            TrustTier::Unknown
        );
        assert_eq!(
            store
                .classify(&process(&executable, 501, "TEAM", "com.example.wrong"), 501,)
                .tier,
            TrustTier::Unknown
        );
    }

    #[test]
    fn same_basename_wrong_path_and_cross_uid_are_untrusted() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("Chrome.app/Contents/MacOS/Chrome");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"signed fixture").unwrap();
        let store = MacBrowserTrustStore::load_and_revalidate(vec![signed_browser(
            temp.path(),
            &executable,
            BrowserExecutableRole::Main,
        )])
        .unwrap();
        let other = temp.path().join("other/Chrome");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        std::fs::write(&other, b"malicious fixture").unwrap();
        assert_eq!(
            store
                .classify(&process(&other, 501, "TEAM", "com.example.chrome"), 501)
                .tier,
            TrustTier::Unknown
        );
        assert_eq!(
            store
                .classify(
                    &process(&executable, 502, "TEAM", "com.example.chrome"),
                    501,
                )
                .tier,
            TrustTier::Unknown
        );
    }

    #[test]
    fn helper_must_be_inside_enrolled_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let outside = temp.path().join("outside/Chrome Helper");
        std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
        std::fs::write(&outside, b"helper").unwrap();
        let enrollment = signed_browser(temp.path(), &outside, BrowserExecutableRole::Helper);
        assert!(MacBrowserTrustStore::load_and_revalidate(vec![enrollment]).is_err());
    }

    #[test]
    fn signed_helper_update_may_change_framework_version_not_suffix_or_signer() {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("Chrome.app");
        let suffix = PathBuf::from("Chrome Helper.app/Contents/MacOS/Chrome Helper");
        let old = bundle
            .join("Contents/Frameworks/Chrome.framework/Versions/1/Helpers")
            .join(&suffix);
        let new = bundle
            .join("Contents/Frameworks/Chrome.framework/Versions/2/Helpers")
            .join(&suffix);
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::create_dir_all(new.parent().unwrap()).unwrap();
        std::fs::write(&old, b"old signed helper").unwrap();
        std::fs::write(&new, b"new signed helper").unwrap();
        let enrollment = MacBrowserEnrollment {
            browser_id: BrowserId("chrome".to_owned()),
            family: BrowserFamily::Chromium,
            profile_root: temp.path().join("profile"),
            owner_uid: 501,
            app_bundle: Some(bundle),
            executables: vec![MacExecutableEnrollment::Signed {
                role: BrowserExecutableRole::Helper,
                path: old,
                bundle_suffix: Some(suffix),
                team_id: "TEAM".to_owned(),
                signing_id: "com.example.chrome.helper".to_owned(),
            }],
        };
        let store = MacBrowserTrustStore::load_and_revalidate(vec![enrollment]).unwrap();
        assert!(store
            .classify(
                &process(&new, 501, "TEAM", "com.example.chrome.helper"),
                501,
            )
            .tier
            .is_trusted());
    }

    #[test]
    fn changed_custom_bytes_invalidate_explicit_hash() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("custom-browser");
        std::fs::write(&executable, b"version one").unwrap();
        let enrolled = enroll_custom_executable(&executable).unwrap();
        let browser = MacBrowserEnrollment {
            browser_id: BrowserId("custom".to_owned()),
            family: BrowserFamily::Chromium,
            profile_root: temp.path().join("profile"),
            owner_uid: std::fs::metadata(temp.path()).unwrap().uid(),
            app_bundle: None,
            executables: vec![enrolled],
        };
        std::fs::write(&executable, b"version two has changed").unwrap();
        assert!(MacBrowserTrustStore::load_and_revalidate(vec![browser]).is_err());
    }
}
