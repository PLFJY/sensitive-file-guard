use std::collections::HashMap;

use guard_browser::{CustomProfile, ProtectedResourceRegistry, TreeRoot};
use guard_core::resource::{
    BrowserFamily, BrowserId, ProfileId, ProtectedResource, ProtectedResourceId,
    ProtectedResourceKind,
};

use crate::browser_trust::MacBrowserEnrollment;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Default)]
pub struct MacResourceIndex {
    files: HashMap<FileIdentity, ProtectedResource>,
    tree_roots: HashMap<FileIdentity, TreeRoot>,
    profiles: Vec<MacProfileScope>,
}

#[derive(Debug)]
struct MacProfileScope {
    browser: BrowserId,
    family: BrowserFamily,
    root: std::path::PathBuf,
    owner_uid: u32,
    firefox_single_profile: bool,
}

impl MacResourceIndex {
    pub fn from_registry(registry: &ProtectedResourceRegistry) -> anyhow::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let mut index = Self::default();
        for resource in registry.files() {
            let metadata = std::fs::metadata(&resource.path)?;
            index.files.insert(
                FileIdentity {
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                },
                resource.clone(),
            );
        }
        for tree in registry.trees() {
            let metadata = std::fs::metadata(&tree.dir)?;
            index.tree_roots.insert(
                FileIdentity {
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                },
                tree.clone(),
            );
        }
        Ok(index)
    }

    pub fn from_browser_enrollments(enrollments: &[MacBrowserEnrollment]) -> anyhow::Result<Self> {
        let registry = build_browser_registry(enrollments)?;
        let mut index = Self::from_registry(&registry)?;
        index.profiles = enrollments
            .iter()
            .map(|enrollment| MacProfileScope {
                browser: enrollment.browser_id.clone(),
                family: enrollment.family,
                root: enrollment.profile_root.clone(),
                owner_uid: enrollment.owner_uid,
                firefox_single_profile: enrollment.profile_root.join("cookies.sqlite").is_file(),
            })
            .collect();
        Ok(index)
    }

    pub fn concrete(&self, identity: FileIdentity) -> Option<&ProtectedResource> {
        self.files.get(&identity)
    }

    /// Classify one ES target without rescanning a profile. Concrete files are
    /// anchored by file identity so a hardlink cannot evade the exact-file
    /// registry; dynamic descendants use the already-enrolled tree prefixes.
    pub fn classify(
        &self,
        path: &std::path::Path,
        identity: FileIdentity,
    ) -> Option<ProtectedResource> {
        if let Some(resource) = self.concrete(identity) {
            return Some(resource.clone());
        }
        self.tree_roots
            .values()
            .find_map(|tree| {
                path.starts_with(&tree.dir).then(|| ProtectedResource {
                    id: ProtectedResourceId(path.to_string_lossy().into_owned()),
                    kind: tree.kind,
                    owner_uid: tree.owner_uid,
                    browser: Some(tree.browser.clone()),
                    profile: Some(tree.profile.clone()),
                    path: path.to_path_buf(),
                })
            })
            .or_else(|| {
                self.profiles
                    .iter()
                    .find_map(|profile| profile.classify(path))
            })
    }

    pub fn resources(&self) -> impl Iterator<Item = &ProtectedResource> {
        self.files.values()
    }

    pub fn trees(&self) -> impl Iterator<Item = &TreeRoot> {
        self.tree_roots.values()
    }

    pub fn concrete_count(&self) -> usize {
        self.files.len()
    }

    pub fn tree_root_count(&self) -> usize {
        self.tree_roots.len()
    }
}

impl MacProfileScope {
    fn classify(&self, path: &std::path::Path) -> Option<ProtectedResource> {
        let relative = path.strip_prefix(&self.root).ok()?;
        let (profile, kind) = match self.family {
            BrowserFamily::Chromium => self.classify_chromium(relative)?,
            BrowserFamily::Firefox | BrowserFamily::Zen => self.classify_firefox(relative)?,
        };
        Some(ProtectedResource {
            id: ProtectedResourceId(path.to_string_lossy().into_owned()),
            kind,
            owner_uid: self.owner_uid,
            browser: Some(self.browser.clone()),
            profile: Some(ProfileId(profile)),
            path: path.to_path_buf(),
        })
    }

    fn classify_chromium(
        &self,
        relative: &std::path::Path,
    ) -> Option<(String, ProtectedResourceKind)> {
        if relative == std::path::Path::new("Local State") {
            return Some((
                guard_browser::chromium::LOCAL_STATE_PROFILE.into(),
                ProtectedResourceKind::BrowserKeyMaterial,
            ));
        }
        let mut components = relative.components();
        let profile = components
            .next()?
            .as_os_str()
            .to_string_lossy()
            .into_owned();
        if profile != "Default" && !profile.starts_with("Profile ") {
            return None;
        }
        let profile_relative = components.as_path();
        classify_chromium_profile_path(profile_relative).map(|kind| (profile, kind))
    }

    fn classify_firefox(
        &self,
        relative: &std::path::Path,
    ) -> Option<(String, ProtectedResourceKind)> {
        let (profile, profile_relative) = if self.firefox_single_profile {
            (
                self.root
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "profile".into()),
                relative,
            )
        } else {
            let mut components = relative.components();
            (
                components
                    .next()?
                    .as_os_str()
                    .to_string_lossy()
                    .into_owned(),
                components.as_path(),
            )
        };
        classify_firefox_profile_path(profile_relative).map(|kind| (profile, kind))
    }
}

fn classify_chromium_profile_path(path: &std::path::Path) -> Option<ProtectedResourceKind> {
    use guard_browser::chromium::{classify_profile_relative, Classified};

    match classify_profile_relative(path) {
        Classified::File(kind) => Some(kind),
        Classified::Tree(kind) => Some(kind),
        Classified::None => path.ancestors().skip(1).find_map(|ancestor| {
            if let Classified::Tree(kind) = classify_profile_relative(ancestor) {
                Some(kind)
            } else {
                None
            }
        }),
    }
}

fn classify_firefox_profile_path(path: &std::path::Path) -> Option<ProtectedResourceKind> {
    use guard_browser::firefox::{classify_profile_relative, Classified};

    match classify_profile_relative(path) {
        Classified::File(kind) => Some(kind),
        Classified::Tree(kind) => Some(kind),
        Classified::None => path.ancestors().skip(1).find_map(|ancestor| {
            if let Classified::Tree(kind) = classify_profile_relative(ancestor) {
                Some(kind)
            } else {
                None
            }
        }),
    }
}

pub fn build_browser_registry(
    enrollments: &[MacBrowserEnrollment],
) -> anyhow::Result<ProtectedResourceRegistry> {
    let mut registry = ProtectedResourceRegistry::new();
    for enrollment in enrollments {
        CustomProfile {
            browser: enrollment.browser_id.clone(),
            family: enrollment.family,
            root: enrollment.profile_root.clone(),
            owner_uid: enrollment.owner_uid,
        }
        .enroll_into(&mut registry)?;
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_core::resource::{ProtectedResourceId, ProtectedResourceKind};
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn concrete_resource_is_indexed_by_inode_identity() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("synthetic-cookie");
        std::fs::write(&path, b"synthetic").unwrap();
        let resource = ProtectedResource {
            id: ProtectedResourceId("synthetic".to_owned()),
            kind: ProtectedResourceKind::CookieStore,
            owner_uid: std::fs::metadata(&path).unwrap().uid(),
            browser: None,
            profile: None,
            path: path.clone(),
        };
        let mut registry = ProtectedResourceRegistry::new();
        registry.enroll_file(resource);
        let index = MacResourceIndex::from_registry(&registry).unwrap();
        let metadata = std::fs::metadata(path).unwrap();
        assert!(index
            .concrete(FileIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            })
            .is_some());
    }

    #[test]
    fn browser_enrollment_reuses_portable_chromium_classifier() {
        use guard_core::resource::{BrowserFamily, BrowserId};

        let temp = tempfile::tempdir().unwrap();
        let profile_root = temp.path().join("Chrome");
        let profile = profile_root.join("Default");
        std::fs::create_dir_all(profile.join("Network")).unwrap();
        std::fs::write(profile_root.join("Local State"), b"synthetic").unwrap();
        std::fs::write(profile.join("Network/Cookies"), b"synthetic").unwrap();
        let enrollment = MacBrowserEnrollment {
            browser_id: BrowserId("chrome".to_owned()),
            family: BrowserFamily::Chromium,
            profile_root,
            owner_uid: 501,
            app_bundle: None,
            executables: vec![],
        };
        let registry = build_browser_registry(&[enrollment]).unwrap();
        assert_eq!(registry.file_count(), 2);
    }

    #[test]
    fn concrete_alias_uses_file_identity_and_tree_descendants_need_no_rescan() {
        let temp = tempfile::tempdir().unwrap();
        let tree = temp.path().join("profile/Local Storage");
        std::fs::create_dir_all(&tree).unwrap();
        let concrete = temp.path().join("profile/Cookies");
        std::fs::write(&concrete, b"synthetic").unwrap();
        let alias = temp.path().join("cookie-alias");
        std::fs::hard_link(&concrete, &alias).unwrap();
        let mut registry = ProtectedResourceRegistry::new();
        registry.enroll_file(ProtectedResource {
            id: ProtectedResourceId("cookies".into()),
            kind: ProtectedResourceKind::CookieStore,
            owner_uid: 501,
            browser: Some(guard_core::resource::BrowserId("chrome".into())),
            profile: Some(guard_core::resource::ProfileId("Default".into())),
            path: concrete,
        });
        registry.enroll_tree(TreeRoot {
            dir: tree.clone(),
            browser: guard_core::resource::BrowserId("chrome".into()),
            profile: guard_core::resource::ProfileId("Default".into()),
            kind: ProtectedResourceKind::WebStorage,
            owner_uid: 501,
        });
        let index = MacResourceIndex::from_registry(&registry).unwrap();
        let alias_metadata = std::fs::metadata(&alias).unwrap();
        assert_eq!(
            index
                .classify(
                    &alias,
                    FileIdentity {
                        dev: alias_metadata.dev(),
                        ino: alias_metadata.ino(),
                    },
                )
                .unwrap()
                .kind,
            ProtectedResourceKind::CookieStore
        );
        let new_descendant = tree.join("origin/entry");
        assert_eq!(
            index
                .classify(&new_descendant, FileIdentity { dev: 9, ino: 10 })
                .unwrap()
                .kind,
            ProtectedResourceKind::WebStorage
        );
    }

    #[test]
    fn newly_created_browser_resources_use_pure_profile_patterns_without_rescan() {
        use guard_core::resource::{BrowserFamily, BrowserId};

        let temp = tempfile::tempdir().unwrap();
        let chromium_root = temp.path().join("chromium");
        std::fs::create_dir_all(chromium_root.join("Default")).unwrap();
        let firefox_root = temp.path().join("firefox-profiles");
        std::fs::create_dir_all(firefox_root.join("alpha.default")).unwrap();
        let index = MacResourceIndex::from_browser_enrollments(&[
            MacBrowserEnrollment {
                browser_id: BrowserId("chrome".into()),
                family: BrowserFamily::Chromium,
                profile_root: chromium_root.clone(),
                owner_uid: 501,
                app_bundle: None,
                executables: vec![],
            },
            MacBrowserEnrollment {
                browser_id: BrowserId("firefox".into()),
                family: BrowserFamily::Firefox,
                profile_root: firefox_root.clone(),
                owner_uid: 501,
                app_bundle: None,
                executables: vec![],
            },
        ])
        .unwrap();

        let login_data = chromium_root.join("Default/Login Data");
        std::fs::write(&login_data, b"created after indexing").unwrap();
        assert_eq!(
            index
                .classify(&login_data, FileIdentity { dev: 77, ino: 88 })
                .unwrap()
                .kind,
            ProtectedResourceKind::SavedCredentials
        );
        let storage = firefox_root.join("alpha.default/storage/default/origin/data.sqlite");
        std::fs::create_dir_all(storage.parent().unwrap()).unwrap();
        std::fs::write(&storage, b"created after indexing").unwrap();
        assert_eq!(
            index
                .classify(&storage, FileIdentity { dev: 99, ino: 100 })
                .unwrap()
                .kind,
            ProtectedResourceKind::WebStorage
        );
        assert!(index
            .classify(
                &chromium_root.join("Default/Cache/cache-entry"),
                FileIdentity { dev: 3, ino: 4 },
            )
            .is_none());
    }
}
