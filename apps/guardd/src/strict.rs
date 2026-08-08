//! Strict filesystem-wide event classification.
//!
//! A filesystem mark causes unrelated opens to reach guardd. This classifier
//! performs only fstat, a read lock over the small protected-inode index, and
//! `/proc/self/fd` readlink/path matching. Process identity and policy are
//! intentionally deferred until a protected candidate is found.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use guard_core::resource::{
    BrowserFamily, BrowserId, ProfileId, ProtectedResource, ProtectedResourceId,
    ProtectedResourceKind,
};
use platform_linux::fanotify;

use crate::enforce::{EnforcementConfig, EnforcementMode, InodeIndex};

pub struct BackendMetrics {
    pub mode: EnforcementMode,
    pub marked_filesystems: AtomicUsize,
    pub strict_events_total: AtomicU64,
    pub strict_fast_allowed: AtomicU64,
    pub protected_events: AtomicU64,
    pub fanotify_overflows: AtomicU64,
    pub classifier_failures: AtomicU64,
    pub strict_alias_scans: AtomicU64,
    pub strict_alias_matches: AtomicU64,
}

impl BackendMetrics {
    pub fn new(mode: EnforcementMode) -> Self {
        Self {
            mode,
            marked_filesystems: AtomicUsize::new(0),
            strict_events_total: AtomicU64::new(0),
            strict_fast_allowed: AtomicU64::new(0),
            protected_events: AtomicU64::new(0),
            fanotify_overflows: AtomicU64::new(0),
            classifier_failures: AtomicU64::new(0),
            strict_alias_scans: AtomicU64::new(0),
            strict_alias_matches: AtomicU64::new(0),
        }
    }

    pub fn marked_filesystems(&self) -> usize {
        self.marked_filesystems.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> BackendSnapshot {
        BackendSnapshot {
            marked_filesystems: self.marked_filesystems(),
            strict_events_total: self.strict_events_total.load(Ordering::Relaxed),
            strict_fast_allowed: self.strict_fast_allowed.load(Ordering::Relaxed),
            protected_events: self.protected_events.load(Ordering::Relaxed),
            fanotify_overflows: self.fanotify_overflows.load(Ordering::Relaxed),
            classifier_failures: self.classifier_failures.load(Ordering::Relaxed),
            strict_alias_scans: self.strict_alias_scans.load(Ordering::Relaxed),
            strict_alias_matches: self.strict_alias_matches.load(Ordering::Relaxed),
        }
    }
}

pub struct BackendSnapshot {
    pub marked_filesystems: usize,
    pub strict_events_total: u64,
    pub strict_fast_allowed: u64,
    pub protected_events: u64,
    pub fanotify_overflows: u64,
    pub classifier_failures: u64,
    pub strict_alias_scans: u64,
    pub strict_alias_matches: u64,
}

#[derive(Debug)]
pub enum StrictClassification {
    Protected(ProtectedResource),
    Unrelated,
    Error(String),
}

#[derive(Debug, Clone)]
struct BrowserNamespace {
    browser: BrowserId,
    family: BrowserFamily,
    root: PathBuf,
    owner_uid: u32,
}

#[derive(Debug, Clone)]
struct SshNamespace {
    path: PathBuf,
    owner_uid: u32,
}

pub struct StrictClassifier {
    browsers: Vec<BrowserNamespace>,
    ssh: Vec<SshNamespace>,
    inode_index: InodeIndex,
    filesystem_paths: Vec<PathBuf>,
    metrics: std::sync::Arc<BackendMetrics>,
}

impl StrictClassifier {
    pub fn new(
        cfg: &EnforcementConfig,
        inode_index: InodeIndex,
        metrics: std::sync::Arc<BackendMetrics>,
    ) -> anyhow::Result<Self> {
        let mut browsers = Vec::with_capacity(cfg.browsers.len());
        let mut ssh = Vec::with_capacity(cfg.ssh_keys.len());
        let mut filesystem_paths = Vec::new();
        let mut devices = HashSet::new();

        for browser in &cfg.browsers {
            let root = std::fs::canonicalize(&browser.profile_root).map_err(|error| {
                anyhow::anyhow!(
                    "strict mode requires existing browser root {}: {error}",
                    browser.profile_root.display()
                )
            })?;
            let metadata = std::fs::metadata(&root)?;
            let owner_uid = browser.owner_uid.unwrap_or(metadata.uid());
            browsers.push(BrowserNamespace {
                browser: BrowserId(browser.id.clone()),
                family: browser.family,
                root: root.clone(),
                owner_uid,
            });
            if devices.insert(metadata.dev()) {
                filesystem_paths.push(root);
            }
        }

        for configured in &cfg.ssh_keys {
            let path = std::fs::canonicalize(configured).map_err(|error| {
                anyhow::anyhow!(
                    "strict mode requires existing configured SSH key {}: {error}",
                    configured.display()
                )
            })?;
            let metadata = std::fs::metadata(&path)?;
            ssh.push(SshNamespace {
                path: path.clone(),
                owner_uid: metadata.uid(),
            });
            if devices.insert(metadata.dev()) {
                filesystem_paths.push(path);
            }
        }

        if filesystem_paths.is_empty() {
            anyhow::bail!("strict-filesystem mode has no protected filesystem to mark");
        }

        Ok(Self {
            browsers,
            ssh,
            inode_index,
            filesystem_paths,
            metrics,
        })
    }

    pub fn filesystem_paths(&self) -> &[PathBuf] {
        &self.filesystem_paths
    }

    pub fn classify_fd(&self, fd: RawFd) -> StrictClassification {
        let identity = match fanotify::fd_identity(fd) {
            Ok(identity) => identity,
            Err(error) => {
                return StrictClassification::Error(format!("fstat event fd failed: {error}"))
            }
        };
        if let Some(resource) = self
            .inode_index
            .read()
            .expect("inode index lock poisoned")
            .get(&identity)
            .cloned()
        {
            return StrictClassification::Protected(resource);
        }

        let path = match fanotify::fd_path(fd) {
            Ok(path) => path,
            Err(error) => {
                return StrictClassification::Error(format!(
                    "readlink event fd path failed: {error}"
                ))
            }
        };
        match self.classify_path(&path) {
            Some(resource) => StrictClassification::Protected(resource),
            None => match fanotify::fd_link_count(fd) {
                Ok(links) if links > 1 => {
                    self.metrics
                        .strict_alias_scans
                        .fetch_add(1, Ordering::Relaxed);
                    match self.find_protected_alias(identity) {
                        Ok(Some(resource)) => {
                            self.metrics
                                .strict_alias_matches
                                .fetch_add(1, Ordering::Relaxed);
                            self.inode_index
                                .write()
                                .expect("inode index lock poisoned")
                                .insert(identity, resource.clone());
                            StrictClassification::Protected(resource)
                        }
                        Ok(None) => StrictClassification::Unrelated,
                        Err(error) => StrictClassification::Error(error),
                    }
                }
                Ok(_) => StrictClassification::Unrelated,
                Err(error) => StrictClassification::Error(format!(
                    "fstat event fd link count failed: {error}"
                )),
            },
        }
    }

    /// An event fd opened through an external hardlink exposes that alias, not
    /// every name of the inode. For the exceptional `st_nlink > 1` case,
    /// synchronously search only enrolled namespaces using directory reads and
    /// metadata (neither opens regular files). This closes the rename+hardlink
    /// first-open gap without penalizing the overwhelmingly common nlink=1
    /// filesystem fast path.
    fn find_protected_alias(
        &self,
        identity: (u64, u64),
    ) -> Result<Option<ProtectedResource>, String> {
        for key in &self.ssh {
            if path_identity(&key.path).ok() == Some(identity) {
                return Ok(self.classify_path(&key.path));
            }
        }
        for browser in &self.browsers {
            for path in find_identity_in_tree(&browser.root, identity)? {
                if let Some(resource) = self.classify_path(&path) {
                    return Ok(Some(resource));
                }
            }
        }
        Ok(None)
    }

    fn classify_path(&self, path: &Path) -> Option<ProtectedResource> {
        for key in &self.ssh {
            if path == key.path {
                return Some(resource(
                    path,
                    ProtectedResourceKind::SshPrivateKey,
                    key.owner_uid,
                    None,
                    None,
                ));
            }
        }
        for namespace in &self.browsers {
            let Ok(relative) = path.strip_prefix(&namespace.root) else {
                continue;
            };
            let classified = match namespace.family {
                BrowserFamily::Chromium => classify_chromium(relative),
                BrowserFamily::Firefox | BrowserFamily::Zen => classify_firefox(relative),
            };
            if let Some((kind, profile)) = classified {
                return Some(resource(
                    path,
                    kind,
                    namespace.owner_uid,
                    Some(namespace.browser.clone()),
                    Some(ProfileId(profile)),
                ));
            }
        }
        None
    }
}

fn path_identity(path: &Path) -> std::io::Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

fn find_identity_in_tree(root: &Path, identity: (u64, u64)) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut matches = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            format!("scan protected namespace {}: {error}", directory.display())
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!("read protected namespace {}: {error}", directory.display())
            })?;
            let path = entry.path();
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "stat protected namespace {}: {error}",
                        path.display()
                    ))
                }
            };
            if (metadata.dev(), metadata.ino()) == identity {
                matches.push(path.clone());
            }
            if metadata.file_type().is_dir() {
                pending.push(path);
            }
        }
    }
    Ok(matches)
}

fn classify_chromium(relative: &Path) -> Option<(ProtectedResourceKind, String)> {
    if relative == Path::new("Local State") {
        return Some((
            ProtectedResourceKind::BrowserKeyMaterial,
            guard_browser::chromium::LOCAL_STATE_PROFILE.to_owned(),
        ));
    }
    let mut components = relative.components();
    let profile = components
        .next()?
        .as_os_str()
        .to_string_lossy()
        .into_owned();
    let tail: PathBuf = components.collect();
    let name = tail.file_name()?.to_str()?;

    if (tail.parent() == Some(Path::new("Network")) || tail.parent() == Some(Path::new("")))
        && name.starts_with("Cookies")
    {
        return Some((ProtectedResourceKind::CookieStore, profile));
    }
    if tail.parent() == Some(Path::new(""))
        && (name.starts_with("Login Data") || name.starts_with("Web Data"))
    {
        return Some((ProtectedResourceKind::SavedCredentials, profile));
    }
    if tail.starts_with("Sessions") || tail.starts_with("Session Storage") {
        return Some((ProtectedResourceKind::SessionStore, profile));
    }
    if tail.starts_with("Local Storage") || tail.starts_with("IndexedDB") {
        return Some((ProtectedResourceKind::WebStorage, profile));
    }
    None
}

fn classify_firefox(relative: &Path) -> Option<(ProtectedResourceKind, String)> {
    if let Some(kind) = classify_firefox_profile_relative(relative) {
        let root_profile = relative.components().count() == 1
            || relative.starts_with("storage")
            || relative.starts_with("sessionstore-backups");
        let profile = if root_profile {
            "(profile-root)".to_owned()
        } else {
            relative
                .components()
                .next()?
                .as_os_str()
                .to_string_lossy()
                .into_owned()
        };
        return Some((kind, profile));
    }

    let mut components = relative.components();
    let profile = components
        .next()?
        .as_os_str()
        .to_string_lossy()
        .into_owned();
    let tail: PathBuf = components.collect();
    classify_firefox_profile_relative(&tail).map(|kind| (kind, profile))
}

fn classify_firefox_profile_relative(relative: &Path) -> Option<ProtectedResourceKind> {
    let name = relative.file_name()?.to_str()?;
    if name.starts_with("cookies.sqlite") {
        return Some(ProtectedResourceKind::CookieStore);
    }
    match name {
        "logins.json" => Some(ProtectedResourceKind::SavedCredentials),
        "key4.db" => Some(ProtectedResourceKind::BrowserKeyMaterial),
        _ if relative.starts_with("sessionstore-backups") => {
            Some(ProtectedResourceKind::SessionStore)
        }
        _ if relative.starts_with("storage") => Some(ProtectedResourceKind::WebStorage),
        _ => None,
    }
}

fn resource(
    path: &Path,
    kind: ProtectedResourceKind,
    owner_uid: u32,
    browser: Option<BrowserId>,
    profile: Option<ProfileId>,
) -> ProtectedResource {
    ProtectedResource {
        id: ProtectedResourceId(path.to_string_lossy().into_owned()),
        kind,
        path: path.to_path_buf(),
        owner_uid,
        browser,
        profile,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn chromium_config(root: &Path) -> EnforcementConfig {
        EnforcementConfig {
            enforcement_mode: EnforcementMode::StrictFilesystem,
            browsers: vec![crate::enforce::BrowserEnrollmentConfig {
                id: "synthetic-chromium".to_owned(),
                family: BrowserFamily::Chromium,
                profile_root: root.to_path_buf(),
                owner_uid: Some(1000),
                exe_paths: Vec::new(),
            }],
            enrolled_exes: Vec::new(),
            ssh_keys: Vec::new(),
        }
    }

    #[test]
    fn chromium_namespace_patterns_cover_first_open_targets() {
        for path in [
            "Default/Network/Cookies",
            "Default/Network/Cookies-wal",
            "Default/Cookies-shm",
            "Default/Login Data-journal",
            "Default/Web Data",
            "Default/Sessions/new/Session_1",
            "Profile 2/Session Storage/000001.log",
            "Profile 2/Local Storage/leveldb/000001.ldb",
            "Profile 2/IndexedDB/site/000001.log",
        ] {
            assert!(classify_chromium(Path::new(path)).is_some(), "{path}");
        }
        assert_eq!(
            classify_chromium(Path::new("Local State")).unwrap().0,
            ProtectedResourceKind::BrowserKeyMaterial
        );
        assert!(classify_chromium(Path::new("Default/History")).is_none());
        assert!(classify_chromium(Path::new("Default/cache/Login Data.old")).is_none());
    }

    #[test]
    fn firefox_namespace_patterns_cover_root_and_nested_profiles() {
        for path in [
            "cookies.sqlite",
            "cookies.sqlite-wal",
            "logins.json",
            "key4.db",
            "storage/default/site/data.sqlite",
            "sessionstore-backups/recovery.jsonlz4",
            "profile-a/cookies.sqlite-shm",
            "profile-a/logins.json",
            "profile-a/key4.db",
            "profile-a/storage/default/site/data.sqlite",
            "profile-a/sessionstore-backups/previous.jsonlz4",
        ] {
            assert!(classify_firefox(Path::new(path)).is_some(), "{path}");
        }
        assert!(classify_firefox(Path::new("profile-a/places.sqlite")).is_none());
    }

    #[test]
    fn external_hardlink_of_replacement_is_found_before_inode_index_refresh() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("chromium");
        let target = root.join("Default/Network/Cookies");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        let replacement = temp.path().join("replacement");
        let alias = temp.path().join("external-alias");
        std::fs::write(&replacement, b"synthetic").unwrap();
        std::fs::hard_link(&replacement, &alias).unwrap();
        std::fs::rename(&replacement, &target).unwrap();

        let index = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let metrics = std::sync::Arc::new(BackendMetrics::new(EnforcementMode::StrictFilesystem));
        let classifier = StrictClassifier::new(
            &chromium_config(&root),
            std::sync::Arc::clone(&index),
            std::sync::Arc::clone(&metrics),
        )
        .unwrap();
        let file = std::fs::File::open(&alias).unwrap();
        assert!(matches!(
            classifier.classify_fd(file.as_raw_fd()),
            StrictClassification::Protected(_)
        ));
        assert_eq!(metrics.strict_alias_scans.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.strict_alias_matches.load(Ordering::Relaxed), 1);
        assert_eq!(index.read().unwrap().len(), 1);
    }

    #[test]
    fn strict_configuration_requires_an_existing_protected_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let metrics = std::sync::Arc::new(BackendMetrics::new(EnforcementMode::StrictFilesystem));
        let index = std::sync::Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
        let error = StrictClassifier::new(&chromium_config(&missing), index, metrics)
            .err()
            .expect("missing root must fail strict startup");
        assert!(error.to_string().contains("requires existing browser root"));
    }
}
