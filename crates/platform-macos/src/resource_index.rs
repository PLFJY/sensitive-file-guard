use std::collections::HashMap;

use guard_browser::{CustomProfile, ProtectedResourceRegistry};
use guard_core::resource::ProtectedResource;

use crate::browser_trust::MacBrowserEnrollment;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Default)]
pub struct MacResourceIndex {
    files: HashMap<FileIdentity, ProtectedResource>,
    tree_roots: HashMap<FileIdentity, std::path::PathBuf>,
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
                tree.dir.clone(),
            );
        }
        Ok(index)
    }

    pub fn concrete(&self, identity: FileIdentity) -> Option<&ProtectedResource> {
        self.files.get(&identity)
    }

    pub fn concrete_count(&self) -> usize {
        self.files.len()
    }

    pub fn tree_root_count(&self) -> usize {
        self.tree_roots.len()
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
}
