use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use guard_core::identity::{ProcessIdentity, ProcessIntegrity, ProcessStableId, TrustTier};

use crate::process_shield::MacProcessShield;
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
        /// P2-7 review: every ExplicitHash enrollment today is a user-enrolled
        /// browser MAIN executable (Safari and custom browsers enrolled via
        /// the GUI). Carrying the role in the enrollment prevents the
        /// launch-topology model from misclassifying a legitimately launched
        /// Safari/custom browser as a laundered helper (Rejected(
        /// ExternalLaunch)) just because ExplicitHash previously had no role.
        /// Old configurations without the field default to Main.
        #[serde(default = "default_explicit_hash_role")]
        role: BrowserExecutableRole,
        path: PathBuf,
        dev: u64,
        ino: u64,
        size: u64,
        mtime_ns: i64,
        ctime_ns: i64,
        sha256: [u8; 32],
    },
}

/// Serde default for ExplicitHash::role: user-enrolled executables are browser
/// mains (P2-7 review).
fn default_explicit_hash_role() -> BrowserExecutableRole {
    BrowserExecutableRole::Main
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
    /// MCH3: the enrolled role of the matched executable (Main / Helper), when
    /// the enrollment carries one. `None` for ExplicitHash (user-enrolled)
    /// enrollments or unknown processes. This is BROWSER IDENTITY context only
    /// (launch-topology bookkeeping); it never grants task authority by itself.
    pub role: Option<BrowserExecutableRole>,
}

impl BrowserTrustDecision {
    fn unknown() -> Self {
        Self {
            browser: None,
            tier: TrustTier::Unknown,
            role: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MacBrowserTrustStore {
    browsers: Vec<MacBrowserEnrollment>,
}

impl MacBrowserTrustStore {
    /// All enrolled executable paths (signed and explicit-hash entries) for
    /// cheap Process Shield AUTH_EXEC scope gating. Path matching here is
    /// deliberately not an authority: the full identity/signature verify
    /// happens on the normalized target before any admission.
    pub fn enrolled_executable_paths(&self) -> Vec<PathBuf> {
        self.browsers
            .iter()
            .flat_map(|browser| &browser.executables)
            .map(|executable| executable.path().to_path_buf())
            .collect()
    }
}

pub struct MacProcessIdentityResolver {
    graph: std::sync::Arc<std::sync::Mutex<MacProcessGraph>>,
    trust: std::sync::Arc<std::sync::RwLock<MacBrowserTrustStore>>,
    shield: Option<std::sync::Arc<std::sync::Mutex<MacProcessShield>>>,
    /// MCH0: runtime Process Shield toggle shared with guard-es and the ES
    /// backend. None means enabled (tests / legacy). When disabled, the
    /// resolver never warm-start-reconciles a trusted browser into the shield
    /// and always surfaces Normal integrity, so File Shield stays independent.
    /// Interior mutability because the resolver is shared behind an Arc.
    process_shield_enabled: std::sync::Mutex<Option<std::sync::Arc<std::sync::atomic::AtomicBool>>>,
}

impl MacProcessIdentityResolver {
    pub fn new(
        graph: std::sync::Arc<std::sync::Mutex<MacProcessGraph>>,
        trust: MacBrowserTrustStore,
    ) -> Self {
        Self {
            graph,
            trust: std::sync::Arc::new(std::sync::RwLock::new(trust)),
            shield: None,
            process_shield_enabled: std::sync::Mutex::new(None),
        }
    }

    pub fn new_shared(
        graph: std::sync::Arc<std::sync::Mutex<MacProcessGraph>>,
        trust: std::sync::Arc<std::sync::RwLock<MacBrowserTrustStore>>,
    ) -> Self {
        Self {
            graph,
            trust,
            shield: None,
            process_shield_enabled: std::sync::Mutex::new(None),
        }
    }

    /// Shared resolver that also consults the live Process Shield state so a
    /// Compromised exact instance fails closed before any browser/SSH policy.
    pub fn new_shared_with_shield(
        graph: std::sync::Arc<std::sync::Mutex<MacProcessGraph>>,
        trust: std::sync::Arc<std::sync::RwLock<MacBrowserTrustStore>>,
        shield: std::sync::Arc<std::sync::Mutex<MacProcessShield>>,
    ) -> Self {
        Self {
            graph,
            trust,
            shield: Some(shield),
            process_shield_enabled: std::sync::Mutex::new(None),
        }
    }

    pub fn replace_trust(&self, trust: MacBrowserTrustStore) -> anyhow::Result<()> {
        *self
            .trust
            .write()
            .map_err(|_| anyhow::anyhow!("macOS browser trust lock is poisoned"))? = trust;
        Ok(())
    }

    /// MCH0: wire the shared Process Shield toggle. None means enabled.
    pub fn set_process_shield_enabled(
        &self,
        flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) {
        *self
            .process_shield_enabled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = flag;
    }

    /// True when Process Shield enforcement is active (None flag means
    /// enabled).
    pub fn shield_enabled(&self) -> bool {
        self.process_shield_enabled
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_none_or(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
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
        // P1 review (promotion timing): resolve() is a pure identity
        // resolution. It must NOT promote a process to SecretAuthority merely
        // because a protected event is being resolved: promotion is a security
        // authority transition that belongs only at the point where the policy
        // has decided to ALLOW protected secret bytes (see
        // MacProcessIdentityResolver::promote_authority, called by the
        // File Shield ALLOW path). Resolving an event that will ultimately be
        // DENIED, or a write-only open, must never grant authority.
        let integrity = if !self.shield_enabled() {
            // MCH0: Process Shield disabled -> the live shield state (stale
            // entries from before the toggle) never influences File Shield;
            // every process is Normal for integrity purposes.
            ProcessIntegrity::Normal
        } else {
            self.shield
                .as_ref()
                .map(|shield| {
                    shield
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .integrity_of_pid(pid)
                })
                .unwrap_or(ProcessIntegrity::Normal)
        };
        Ok(ProcessIdentity {
            stable: facts.stable_id(),
            uid: facts.uid,
            gid: facts.gid,
            exe_owner_uid: facts.executable.owner_uid,
            browser: trust.browser,
            trust_tier: trust.tier,
            cmdline: Vec::new(),
            ancestors,
            // Process Shield live state: a Compromised exact instance is
            // surfaced here so the portable policy fails it closed before any
            // browser/SSH rule. Without a shield (tests/legacy), Normal.
            integrity,
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

impl MacProcessIdentityResolver {
    /// P1 review (MCH5 rework): runtime SecretAuthority promotion, called ONLY
    /// by the File Shield ALLOW path once the policy has decided to grant
    /// protected secret bytes to a trusted browser process. Fail closed:
    /// admission errors (invalid identity, provably externally launched
    /// signed-helper laundering) DENY the read instead of proceeding
    /// unshielded. With Process Shield disabled no promotion happens (File
    /// Shield judges alone). Idempotent for already-task-protected instances.
    pub fn promote_authority(&self, facts: &MacProcessFacts) -> anyhow::Result<()> {
        if !self.shield_enabled() {
            return Ok(());
        }
        let Some(shield) = &self.shield else {
            return Ok(());
        };
        let mut shield = shield
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // Idempotent for instances that already carry browser SecretAuthority.
        // An instance shielded only by a dynamic lease reason must still get
        // its browser authority recorded (so lease expiry keeps it protected
        // as a browser), so the short-circuit is on browser authority, not on
        // generic task protection.
        if shield.is_browser_authority(facts) {
            return Ok(());
        }
        shield.ensure_authority(facts).map_err(|error| {
            anyhow::anyhow!(
                "failed to admit trusted browser as SecretAuthority before protected bytes were allowed: {error}"
            )
        })
    }

    /// The live Process Shield state, when wired (MPS5/MPS6).
    pub fn shield(&self) -> Option<std::sync::Arc<std::sync::Mutex<MacProcessShield>>> {
        self.shield.clone()
    }

    /// Current graph facts for a PID, for dynamic lease-root shielding
    /// (MPS6).
    pub fn current_facts(&self, pid: u32) -> Option<MacProcessFacts> {
        self.graph
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .current(pid)
            .cloned()
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
                        role: match executable {
                            MacExecutableEnrollment::Signed { role, .. } => Some(*role),
                            MacExecutableEnrollment::ExplicitHash { role, .. } => Some(*role),
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
        role: BrowserExecutableRole::Main,
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
        ..
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
    use guard_platform::ProcessIdentityResolver;
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
    fn resolve_is_pure_and_promote_authority_admits_warm_start_as_preexisting() {
        // P1 review (promotion timing): resolve() is pure identity
        // resolution and must NOT create SecretAuthority. The warm-start
        // reconciliation happens only when the File Shield ALLOW path calls
        // promote_authority().
        use crate::identity::MacProcessGraph;
        use crate::process_shield::{MacProcessShield, ShieldAdmission};
        use std::sync::Arc;
        use std::sync::Mutex;

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
        let graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        let shield = Arc::new(Mutex::new(MacProcessShield::new()));
        let facts = process(&executable, 501, "TEAM", "com.example.chrome");
        graph
            .lock()
            .unwrap()
            .observe(facts.clone(), std::time::Instant::now())
            .unwrap();
        let resolver = MacProcessIdentityResolver::new_shared_with_shield(
            Arc::clone(&graph),
            Arc::new(std::sync::RwLock::new(store)),
            Arc::clone(&shield),
        );
        // resolve() must NOT admit: identity only.
        let identity = resolver.resolve(facts.key.pid, 501).unwrap();
        assert!(identity.browser.is_some());
        assert!(identity.trust_tier.is_trusted());
        assert!(!shield.lock().unwrap().is_shielded_exact(&facts));
        // The File Shield ALLOW path promotes; warm start becomes
        // PreexistingUnverified.
        resolver.promote_authority(&facts).unwrap();
        assert!(shield.lock().unwrap().is_shielded_exact(&facts));
        assert!(shield.lock().unwrap().is_preexisting(facts.key.pid));
        assert_eq!(
            shield.lock().unwrap().admission_of_pid(facts.key.pid),
            Some(ShieldAdmission::PreexistingUnverified)
        );
        assert_eq!(shield.lock().unwrap().live_preexisting_count(), 1);
        // A second promotion is idempotent: still exactly one admission.
        resolver.promote_authority(&facts).unwrap();
        assert_eq!(shield.lock().unwrap().preexisting_admitted_total(), 1);
    }

    #[test]
    fn resolver_with_disabled_shield_skips_warm_start_reconciliation() {
        // MCH0: with Process Shield disabled, a trusted preexisting browser is
        // resolved by File Shield alone: no shield admission, no fail-closed
        // reconciliation, integrity Normal.
        use crate::identity::MacProcessGraph;
        use crate::process_shield::MacProcessShield;
        use std::sync::Arc;
        use std::sync::Mutex;

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
        let graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        let shield = Arc::new(Mutex::new(MacProcessShield::new()));
        let facts = process(&executable, 501, "TEAM", "com.example.chrome");
        graph
            .lock()
            .unwrap()
            .observe(facts.clone(), std::time::Instant::now())
            .unwrap();
        let resolver = MacProcessIdentityResolver::new_shared_with_shield(
            Arc::clone(&graph),
            Arc::new(std::sync::RwLock::new(store)),
            Arc::clone(&shield),
        );
        resolver
            .set_process_shield_enabled(Some(Arc::new(std::sync::atomic::AtomicBool::new(false))));
        let identity = resolver.resolve(facts.key.pid, 501).unwrap();
        assert!(identity.browser.is_some());
        assert!(identity.trust_tier.is_trusted());
        assert_eq!(identity.integrity, guard_core::ProcessIntegrity::Normal);
        // File Shield works; Process Shield state is untouched.
        assert!(!shield.lock().unwrap().is_shielded_exact(&facts));
        assert_eq!(shield.lock().unwrap().live_preexisting_count(), 0);
        assert_eq!(shield.lock().unwrap().preexisting_admitted_total(), 0);
    }

    #[test]
    fn resolver_with_disabled_shield_ignores_stale_compromise_state() {
        // MCH0: a Compromised entry that predates the disable toggle must not
        // influence File Shield while Process Shield is disabled.
        use crate::identity::MacProcessGraph;
        use crate::process_shield::{MacProcessShield, ShieldReasonKind};
        use std::sync::Arc;
        use std::sync::Mutex;

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
        let graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        let shield = Arc::new(Mutex::new(MacProcessShield::new()));
        let facts = process(&executable, 501, "TEAM", "com.example.chrome");
        graph
            .lock()
            .unwrap()
            .observe(facts.clone(), std::time::Instant::now())
            .unwrap();
        shield
            .lock()
            .unwrap()
            .admit(facts.clone(), ShieldReasonKind::Browser)
            .unwrap();
        shield.lock().unwrap().mark_compromised(&facts.key);
        let resolver = MacProcessIdentityResolver::new_shared_with_shield(
            Arc::clone(&graph),
            Arc::new(std::sync::RwLock::new(store)),
            Arc::clone(&shield),
        );
        resolver
            .set_process_shield_enabled(Some(Arc::new(std::sync::atomic::AtomicBool::new(false))));
        let identity = resolver.resolve(facts.key.pid, 501).unwrap();
        assert_eq!(
            identity.integrity,
            guard_core::ProcessIntegrity::Normal,
            "disabled Process Shield must not fail File Shield on stale state"
        );
        // Re-enabling restores the live Compromised posture immediately.
        resolver
            .set_process_shield_enabled(Some(Arc::new(std::sync::atomic::AtomicBool::new(true))));
        let identity = resolver.resolve(facts.key.pid, 501).unwrap();
        assert_eq!(
            identity.integrity,
            guard_core::ProcessIntegrity::Compromised
        );
    }

    #[test]
    fn promote_authority_fails_closed_on_identity_conflict() {
        // P1 review (promotion timing): resolve() is pure; the promotion
        // entry point must fail closed when the exact instance cannot be
        // admitted (same audit key, different stable identity).
        use crate::identity::MacProcessGraph;
        use crate::process_shield::{MacProcessShield, ShieldReasonKind};
        use std::sync::Arc;
        use std::sync::Mutex;

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

        // Graph facts: the current exact instance (start=100).
        let graph_facts = process(&executable, 501, "TEAM", "com.example.chrome");

        // Shield already contains an entry for the SAME audit key
        // (pid=50, pidversion=3) but a DIFFERENT stable identity
        // (start=200). promote_authority must reject this as
        // "same audit key changed stable identity", so the File Shield
        // ALLOW path fails closed instead of granting secret bytes to an
        // unshielded instance.
        let mut shield = MacProcessShield::new();
        let mut conflicting = graph_facts.clone();
        conflicting.start_time_us = 200;
        shield
            .admit_preexisting(conflicting, ShieldReasonKind::Browser)
            .unwrap();

        let graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        graph
            .lock()
            .unwrap()
            .observe(graph_facts.clone(), std::time::Instant::now())
            .unwrap();
        let resolver = MacProcessIdentityResolver::new_shared_with_shield(
            Arc::clone(&graph),
            Arc::new(std::sync::RwLock::new(store)),
            Arc::new(Mutex::new(shield)),
        );

        let result = resolver.promote_authority(&graph_facts);
        let error = match result {
            Ok(_) => panic!("promote_authority must fail closed on identity conflict"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("same audit key changed stable identity"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn promote_authority_admits_session_helper_but_resolve_stays_pure() {
        // P1 review (promotion timing + MCH5 ordering): the File Shield
        // ALLOW path calls promote_authority() BEFORE the protected bytes are
        // allowed; resolve() itself never promotes. A session-member helper
        // (not task-protected at exec time) is admitted as SecretAuthority at
        // the promotion point with AuthExec admission.
        use crate::browser_trust::BrowserExecutableRole;
        use crate::identity::MacProcessGraph;
        use crate::process_shield::{MacProcessShield, ShieldAdmission};
        use std::sync::Arc;
        use std::sync::Mutex;

        let temp = tempfile::tempdir().unwrap();
        let main_exe = temp.path().join("Chrome.app/Contents/MacOS/Chrome");
        std::fs::create_dir_all(main_exe.parent().unwrap()).unwrap();
        std::fs::write(&main_exe, b"signed fixture").unwrap();
        let helper_exe = temp
            .path()
            .join("Chrome.app/Contents/Frameworks/Chrome Helper.app/Contents/MacOS/Chrome Helper");
        std::fs::create_dir_all(helper_exe.parent().unwrap()).unwrap();
        std::fs::write(&helper_exe, b"signed fixture").unwrap();
        let store = MacBrowserTrustStore::load_and_revalidate(vec![
            signed_browser(temp.path(), &main_exe, BrowserExecutableRole::Main),
            signed_browser(temp.path(), &helper_exe, BrowserExecutableRole::Helper),
        ])
        .unwrap();
        let graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        let shield = Arc::new(Mutex::new(MacProcessShield::new()));
        let main = process(&main_exe, 501, "TEAM", "com.example.chrome");
        let mut helper = process(&helper_exe, 501, "TEAM", "com.example.chrome");
        // Distinct exact instance for the helper (the process() helper
        // hardcodes pid 50; a real session has distinct instances).
        helper.key.pid = 51;
        helper.key.pidversion = 4;
        helper.start_time_us = 101;
        // Session topology: Main roots, Helper joins (no shield entry for the
        // helper at exec time, per MCH4).
        {
            let mut shield = shield.lock().unwrap();
            shield
                .admit_browser(main.clone(), Some(BrowserExecutableRole::Main), None, false)
                .unwrap();
            shield
                .admit_browser(
                    helper.clone(),
                    Some(BrowserExecutableRole::Helper),
                    Some(main.key),
                    true,
                )
                .unwrap();
            assert!(!shield.is_task_protected(&helper));
        }
        graph
            .lock()
            .unwrap()
            .observe(helper.clone(), std::time::Instant::now())
            .unwrap();
        let resolver = MacProcessIdentityResolver::new_shared_with_shield(
            Arc::clone(&graph),
            Arc::new(std::sync::RwLock::new(store)),
            Arc::clone(&shield),
        );
        // resolve() stays pure: no admission, no task protection.
        let identity = resolver.resolve(helper.key.pid, 501).unwrap();
        assert!(identity.browser.is_some());
        assert!(identity.trust_tier.is_trusted());
        assert!(!shield.lock().unwrap().is_task_protected(&helper));
        // The promotion point admits the session helper BEFORE the protected
        // bytes are allowed.
        resolver.promote_authority(&helper).unwrap();
        let shield = shield.lock().unwrap();
        assert!(
            shield.is_task_protected(&helper),
            "helper must be admitted as SecretAuthority before the protected bytes are allowed"
        );
        assert_eq!(
            shield.admission_of_pid(helper.key.pid),
            Some(ShieldAdmission::AuthExec),
            "launch-observed session member must not be PreexistingUnverified"
        );
        assert_eq!(shield.live_preexisting_count(), 0);
    }

    #[test]
    fn promote_authority_rejects_externally_launched_helper() {
        // P0 review: signed-helper laundering. A genuine signed helper whose
        // parent is NOT an enrolled browser is Rejected(ExternalLaunch); that
        // rejection is sticky for the exact instance and MUST survive the
        // runtime promotion path: its protected own-profile AUTH_OPEN must
        // DENY (promote_authority fails) and it must never become a
        // SecretAuthority.
        use crate::browser_session::SessionMembership;
        use crate::browser_trust::BrowserExecutableRole;
        use crate::identity::MacProcessGraph;
        use crate::process_shield::{MacProcessShield, ShieldError};
        use std::sync::Arc;
        use std::sync::Mutex;

        let temp = tempfile::tempdir().unwrap();
        let helper_exe = temp
            .path()
            .join("Chrome.app/Contents/Frameworks/Chrome Helper.app/Contents/MacOS/Chrome Helper");
        std::fs::create_dir_all(helper_exe.parent().unwrap()).unwrap();
        std::fs::write(&helper_exe, b"signed fixture").unwrap();
        let store = MacBrowserTrustStore::load_and_revalidate(vec![signed_browser(
            temp.path(),
            &helper_exe,
            BrowserExecutableRole::Helper,
        )])
        .unwrap();
        let graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        let shield = Arc::new(Mutex::new(MacProcessShield::new()));
        let mut helper = process(&helper_exe, 501, "TEAM", "com.example.chrome");
        helper.key.pid = 51;
        helper.key.pidversion = 4;
        helper.start_time_us = 101;
        // Parent facts exist but the parent is NOT an enrolled browser
        // (attacker process / shell): ExternalLaunch.
        let attacker_path = temp.path().join("attacker");
        std::fs::write(&attacker_path, b"attacker binary").unwrap();
        let mut attacker_parent = process(&attacker_path, 501, "TEAM", "com.example.attacker");
        attacker_parent.key.pid = 52;
        attacker_parent.key.pidversion = 4;
        attacker_parent.start_time_us = 102;
        graph
            .lock()
            .unwrap()
            .observe(attacker_parent.clone(), std::time::Instant::now())
            .unwrap();
        let membership = shield
            .lock()
            .unwrap()
            .admit_browser(
                helper.clone(),
                Some(BrowserExecutableRole::Helper),
                Some(attacker_parent.key),
                false,
            )
            .unwrap();
        assert!(
            matches!(membership, SessionMembership::Rejected(_)) && membership.is_external(),
            "attacker-launched helper must be Rejected(ExternalLaunch)"
        );
        graph
            .lock()
            .unwrap()
            .observe(helper.clone(), std::time::Instant::now())
            .unwrap();
        let resolver = MacProcessIdentityResolver::new_shared_with_shield(
            Arc::clone(&graph),
            Arc::new(std::sync::RwLock::new(store)),
            Arc::clone(&shield),
        );
        // The protected own-profile read must fail closed: the externally
        // launched helper can never be promoted to SecretAuthority, and it
        // stays unprotected (never task-protected).
        let error = match resolver.promote_authority(&helper) {
            Ok(()) => panic!("externally launched helper must not be promoted"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("launched externally"),
            "unexpected error: {error}"
        );
        assert!(matches!(
            resolver
                .shield()
                .unwrap()
                .lock()
                .unwrap()
                .ensure_authority(&helper),
            Err(ShieldError::ExternalLaunchRejected)
        ));
        assert!(!shield.lock().unwrap().is_task_protected(&helper));
    }

    #[test]
    fn resolver_does_not_shield_unrelated_processes() {
        use crate::identity::MacProcessGraph;
        use crate::process_shield::MacProcessShield;
        use std::sync::Arc;
        use std::sync::Mutex;

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
        let graph = Arc::new(Mutex::new(MacProcessGraph::default()));
        let shield = Arc::new(Mutex::new(MacProcessShield::new()));
        let unrelated = temp.path().join("unrelated");
        std::fs::write(&unrelated, b"unrelated process").unwrap();
        let facts = process(&unrelated, 501, "TEAM", "com.example.other");
        graph
            .lock()
            .unwrap()
            .observe(facts.clone(), std::time::Instant::now())
            .unwrap();
        let resolver = MacProcessIdentityResolver::new_shared_with_shield(
            Arc::clone(&graph),
            Arc::new(std::sync::RwLock::new(store)),
            Arc::clone(&shield),
        );
        resolver.resolve(facts.key.pid, 501).unwrap();
        assert!(!shield.lock().unwrap().is_shielded_exact(&facts));
        assert_eq!(shield.lock().unwrap().live_preexisting_count(), 0);
    }

    #[test]
    fn explicit_hash_enrollment_carries_main_role() {
        // P2-7 review: user-enrolled ExplicitHash executables (Safari and
        // custom browsers) are browser MAINS. The role is carried in the
        // enrollment (old configs default to Main), so launch-topology
        // classification treats a legitimately launched Safari/custom
        // browser as a session root, never as a laundered helper.
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("custom-browser");
        std::fs::write(&executable, b"version one").unwrap();
        let enrolled = enroll_custom_executable(&executable).unwrap();
        let MacExecutableEnrollment::ExplicitHash { role, path, .. } = &enrolled else {
            panic!("enroll_custom_executable must produce ExplicitHash")
        };
        assert_eq!(*role, BrowserExecutableRole::Main);
        assert_eq!(*path, std::fs::canonicalize(&executable).unwrap());

        // classify() surfaces the role for the exact executable.
        let browser = MacBrowserEnrollment {
            browser_id: BrowserId("custom".to_owned()),
            family: BrowserFamily::Chromium,
            profile_root: temp.path().join("profile"),
            owner_uid: std::fs::metadata(temp.path()).unwrap().uid(),
            app_bundle: None,
            executables: vec![enrolled],
        };
        let store = MacBrowserTrustStore::load_and_revalidate(vec![browser]).unwrap();
        let canonical = std::fs::canonicalize(&executable).unwrap();
        let facts = process(
            &canonical,
            std::fs::metadata(temp.path()).unwrap().uid(),
            "TEAM",
            "com.example.custom",
        );
        let decision = store.classify(&facts, facts.uid);
        assert!(decision.browser.is_some());
        assert!(decision.tier.is_trusted());
        assert_eq!(decision.role, Some(BrowserExecutableRole::Main));

        // And an older serialized enrollment without the role field still
        // deserializes as Main (serde default).
        let mut json = serde_json::to_value(&MacExecutableEnrollment::ExplicitHash {
            role: BrowserExecutableRole::Main,
            path: executable.clone(),
            dev: 0,
            ino: 0,
            size: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            sha256: [0u8; 32],
        })
        .unwrap();
        json.as_object_mut().unwrap().remove("role");
        let legacy: MacExecutableEnrollment = serde_json::from_value(json).unwrap();
        let MacExecutableEnrollment::ExplicitHash { role, .. } = &legacy else {
            panic!("expected ExplicitHash")
        };
        assert_eq!(*role, BrowserExecutableRole::Main);
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
