use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;

use guard_browser::{CustomProfile, ProtectedResourceRegistry, TreeRoot};
use guard_core::resource::{
    BrowserFamily, BrowserId, ProfileId, ProtectedResource, ProtectedResourceId,
    ProtectedResourceKind,
};

use crate::browser_trust::MacBrowserEnrollment;

pub const DEFAULT_ALIAS_CAPACITY: usize = 65_536;

/// A native Endpoint Security target-path rule.  This deliberately stays
/// close to the SDK terminology: the resource index owns *what* is selected;
/// the C boundary owns the Endpoint Security call itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TargetPathRule {
    pub path: PathBuf,
    pub prefix: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetSelectionPlan {
    rules: Vec<TargetPathRule>,
}

impl TargetSelectionPlan {
    pub fn rules(&self) -> &[TargetPathRule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn from_rules(rules: impl IntoIterator<Item = TargetPathRule>) -> Self {
        let rules = rules
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Self { rules }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceScope {
    pub browser: BrowserId,
    pub profile: Option<ProfileId>,
    pub owner_uid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Clone)]
pub struct MacResourceIndex {
    files: HashMap<FileIdentity, ProtectedResource>,
    aliases: HashMap<FileIdentity, ProtectedResource>,
    tree_roots: HashMap<FileIdentity, TreeRoot>,
    profiles: Vec<MacProfileScope>,
    ssh_paths: HashMap<std::path::PathBuf, ProtectedResource>,
    alias_capacity: usize,
    alias_saturated: bool,
    unresolved_external_hardlinks: usize,
}

impl Default for MacResourceIndex {
    fn default() -> Self {
        Self {
            files: HashMap::new(),
            aliases: HashMap::new(),
            tree_roots: HashMap::new(),
            profiles: Vec::new(),
            ssh_paths: HashMap::new(),
            alias_capacity: DEFAULT_ALIAS_CAPACITY,
            alias_saturated: false,
            unresolved_external_hardlinks: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct MacProfileScope {
    browser: BrowserId,
    family: BrowserFamily,
    root: std::path::PathBuf,
    owner_uid: u32,
    firefox_single_profile: bool,
}

impl MacResourceIndex {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
            && self.aliases.is_empty()
            && self.tree_roots.is_empty()
            && self.profiles.is_empty()
            && self.ssh_paths.is_empty()
    }

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
        index.refresh_aliases()?;
        Ok(index)
    }

    pub fn from_enrollments(
        browsers: &[MacBrowserEnrollment],
        ssh_keys: &[std::path::PathBuf],
    ) -> anyhow::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let mut index = Self::from_browser_enrollments(browsers)?;
        for path in ssh_keys {
            let resource = guard_ssh::enroll_key(path)?;
            let metadata = std::fs::metadata(&resource.path)?;
            index.files.insert(
                FileIdentity {
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                },
                resource.clone(),
            );
            index.ssh_paths.insert(resource.path.clone(), resource);
        }
        Ok(index)
    }

    pub fn concrete(&self, identity: FileIdentity) -> Option<&ProtectedResource> {
        self.files
            .get(&identity)
            .or_else(|| self.aliases.get(&identity))
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
        if let Some(resource) = self.ssh_paths.get(path) {
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

    pub fn classify_path(&self, path: &std::path::Path) -> Option<ProtectedResource> {
        if let Some(resource) = self.ssh_paths.get(path) {
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
            .or_else(|| {
                self.files
                    .values()
                    .find(|resource| resource.path == path)
                    .cloned()
            })
    }

    pub fn namespace_scope(&self, path: &std::path::Path) -> Option<NamespaceScope> {
        self.profiles.iter().find_map(|profile| profile.scope(path))
    }

    pub fn contains_protected_path(&self, path: &std::path::Path) -> bool {
        self.files
            .values()
            .any(|resource| resource.path.starts_with(path))
            || self
                .ssh_paths
                .keys()
                .any(|resource| resource.starts_with(path))
            || self
                .tree_roots
                .values()
                .any(|tree| tree.dir.starts_with(path))
            || self
                .profiles
                .iter()
                .any(|profile| profile.root.starts_with(path))
    }

    pub fn observe_alias(&mut self, identity: FileIdentity, resource: ProtectedResource) -> bool {
        if self.files.contains_key(&identity) || self.aliases.contains_key(&identity) {
            return true;
        }
        if self.aliases.len() >= self.alias_capacity {
            self.alias_saturated = true;
            return false;
        }
        self.aliases.insert(identity, resource);
        true
    }

    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }

    pub fn alias_capacity(&self) -> usize {
        self.alias_capacity
    }

    pub fn alias_saturated(&self) -> bool {
        self.alias_saturated
    }

    pub fn refresh_aliases(&mut self) -> anyhow::Result<()> {
        use std::os::unix::fs::MetadataExt;

        self.aliases.clear();
        self.alias_saturated = false;
        self.unresolved_external_hardlinks = 0;
        let roots = self.namespace_scan_roots();
        let mut stack = roots;
        let mut visited = 0usize;
        let mut in_scope_links = HashMap::<FileIdentity, u64>::new();
        let mut observed_links = HashMap::<FileIdentity, u64>::new();
        let mut seen_entries = std::collections::HashSet::<PathBuf>::new();
        while let Some(directory) = stack.pop() {
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in entries {
                let entry = entry?;
                visited = visited.saturating_add(1);
                if visited > self.alias_capacity.saturating_mul(8) {
                    self.alias_saturated = true;
                    return Ok(());
                }
                let file_type = entry.file_type()?;
                if file_type.is_symlink() {
                    continue;
                }
                let path = entry.path();
                if file_type.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !seen_entries.insert(path.clone()) {
                    continue;
                }
                let Some(resource) = self.classify_path(&path) else {
                    continue;
                };
                let metadata = entry.metadata()?;
                let identity = FileIdentity {
                    dev: metadata.dev(),
                    ino: metadata.ino(),
                };
                *in_scope_links.entry(identity).or_default() += 1;
                observed_links.entry(identity).or_insert(metadata.nlink());
                if !self.observe_alias(identity, resource) {
                    return Ok(());
                }
            }
        }
        self.unresolved_external_hardlinks = observed_links
            .into_iter()
            .filter(|(identity, links)| {
                self.concrete(*identity).is_some()
                    && in_scope_links.get(identity).copied().unwrap_or(0) < *links
            })
            .count();
        Ok(())
    }

    /// Build the smallest native selection set from the same policy model used
    /// for Rust classification.  Safari's conceptual enrollment root is
    /// `~/Library`; selecting that prefix would route unrelated Library opens
    /// through the authorization client, so only Safari's actual namespaces
    /// and the exact ancestors needed for rename protection are included.
    pub fn target_selection_plan(&self) -> TargetSelectionPlan {
        let mut rules = Vec::new();
        for resource in self.files.values() {
            rules.push(TargetPathRule {
                path: resource.path.clone(),
                prefix: false,
            });
        }
        for path in self.ssh_paths.keys() {
            rules.push(TargetPathRule {
                path: path.clone(),
                prefix: false,
            });
            if let Some(parent) = path.parent() {
                // A literal parent selects `RENAME`/`LINK` operations that
                // move the key's immediate namespace without subscribing to
                // every descendant of the user's home directory.
                rules.push(TargetPathRule {
                    path: parent.to_path_buf(),
                    prefix: false,
                });
            }
        }
        for tree in self.tree_roots.values() {
            rules.push(TargetPathRule {
                path: tree.dir.clone(),
                prefix: true,
            });
        }
        for profile in &self.profiles {
            match profile.family {
                BrowserFamily::Safari => {
                    let safari = profile.root.join("Safari");
                    let container = profile.root.join("Containers/com.apple.Safari");
                    let library = container.join("Data/Library");
                    rules.extend([
                        TargetPathRule {
                            path: safari,
                            prefix: true,
                        },
                        TargetPathRule {
                            path: container,
                            prefix: false,
                        },
                        TargetPathRule {
                            path: library,
                            prefix: true,
                        },
                        // These literals select namespace moves without making
                        // every descendant of ~/Library observable.
                        TargetPathRule {
                            path: profile.root.join("Containers"),
                            prefix: false,
                        },
                        TargetPathRule {
                            path: profile.root.clone(),
                            prefix: false,
                        },
                    ]);
                }
                BrowserFamily::Chromium | BrowserFamily::Firefox | BrowserFamily::Zen => {
                    rules.push(TargetPathRule {
                        path: profile.root.clone(),
                        prefix: true,
                    });
                    rules.push(TargetPathRule {
                        path: profile.root.clone(),
                        prefix: false,
                    });
                }
            }
        }
        TargetSelectionPlan::from_rules(rules)
    }

    pub fn unresolved_external_hardlink_count(&self) -> usize {
        self.unresolved_external_hardlinks
    }

    fn namespace_scan_roots(&self) -> Vec<PathBuf> {
        let mut roots = BTreeSet::new();
        for profile in &self.profiles {
            match profile.family {
                BrowserFamily::Safari => {
                    roots.insert(profile.root.join("Safari"));
                    roots.insert(
                        profile
                            .root
                            .join("Containers/com.apple.Safari/Data/Library"),
                    );
                }
                BrowserFamily::Chromium | BrowserFamily::Firefox | BrowserFamily::Zen => {
                    roots.insert(profile.root.clone());
                }
            }
        }
        roots.extend(
            self.files
                .values()
                .filter_map(|resource| resource.path.parent().map(PathBuf::from)),
        );
        roots.extend(
            self.ssh_paths
                .keys()
                .filter_map(|path| path.parent().map(PathBuf::from)),
        );
        roots.extend(self.tree_roots.values().map(|tree| tree.dir.clone()));
        roots.into_iter().collect()
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

    pub fn ssh_key_count(&self) -> usize {
        self.ssh_paths.len()
    }

    pub fn is_configured_ssh_resource(&self, resource: &ProtectedResource) -> bool {
        resource.kind == ProtectedResourceKind::SshPrivateKey
            && self.ssh_paths.get(&resource.path) == Some(resource)
    }
}

impl MacProfileScope {
    fn scope(&self, path: &std::path::Path) -> Option<NamespaceScope> {
        let relative = path.strip_prefix(&self.root).ok()?;
        if self.family == BrowserFamily::Safari
            && !guard_browser::safari::is_safari_namespace_path(relative)
        {
            return None;
        }
        let profile = match self.family {
            BrowserFamily::Chromium => {
                if relative == std::path::Path::new("Local State") {
                    Some(ProfileId(
                        guard_browser::chromium::LOCAL_STATE_PROFILE.into(),
                    ))
                } else {
                    let mut components = relative.components();
                    let name = components.next()?.as_os_str().to_string_lossy();
                    if name == "Default" || name.starts_with("Profile ") {
                        Some(ProfileId(name.into_owned()))
                    } else if components.next().is_none() {
                        Some(ProfileId(
                            guard_browser::chromium::LOCAL_STATE_PROFILE.into(),
                        ))
                    } else {
                        None
                    }
                }
            }
            BrowserFamily::Firefox | BrowserFamily::Zen => {
                if self.firefox_single_profile {
                    Some(ProfileId(
                        self.root
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "profile".into()),
                    ))
                } else {
                    Some(ProfileId(
                        relative
                            .components()
                            .next()?
                            .as_os_str()
                            .to_string_lossy()
                            .into_owned(),
                    ))
                }
            }
            BrowserFamily::Safari => Some(ProfileId(guard_browser::safari::PROFILE_ID.into())),
        };
        Some(NamespaceScope {
            browser: self.browser.clone(),
            profile,
            owner_uid: self.owner_uid,
        })
    }

    fn classify(&self, path: &std::path::Path) -> Option<ProtectedResource> {
        let relative = path.strip_prefix(&self.root).ok()?;
        let (profile, kind) = match self.family {
            BrowserFamily::Chromium => self.classify_chromium(relative)?,
            BrowserFamily::Firefox | BrowserFamily::Zen => self.classify_firefox(relative)?,
            BrowserFamily::Safari => self.classify_safari(relative)?,
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

    fn classify_safari(
        &self,
        relative: &std::path::Path,
    ) -> Option<(String, ProtectedResourceKind)> {
        classify_safari_library_path(relative)
            .map(|kind| (guard_browser::safari::PROFILE_ID.into(), kind))
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

fn classify_safari_library_path(path: &std::path::Path) -> Option<ProtectedResourceKind> {
    use guard_browser::safari::{classify_library_relative, Classified};

    match classify_library_relative(path) {
        Classified::File(kind) | Classified::Tree(kind) => Some(kind),
        Classified::None => path.ancestors().skip(1).find_map(|ancestor| {
            if let Classified::Tree(kind) = classify_library_relative(ancestor) {
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

    #[test]
    fn safari_profile_scope_classifies_only_safari_library_paths() {
        use guard_core::resource::{BrowserFamily, BrowserId};

        let temp = tempfile::tempdir().unwrap();
        let library = temp.path().join("Library");
        std::fs::create_dir_all(
            library.join("Containers/com.apple.Safari/Data/Library/HTTPStorages"),
        )
        .unwrap();
        std::fs::create_dir_all(library.join("Application Support/Google/Chrome")).unwrap();
        let index = MacResourceIndex::from_browser_enrollments(&[MacBrowserEnrollment {
            browser_id: BrowserId("safari".into()),
            family: BrowserFamily::Safari,
            profile_root: library.clone(),
            owner_uid: 501,
            app_bundle: None,
            executables: vec![],
        }])
        .unwrap();

        let cookie =
            library.join("Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies");
        std::fs::create_dir_all(cookie.parent().unwrap()).unwrap();
        std::fs::write(&cookie, b"synthetic Safari cookie marker").unwrap();
        assert_eq!(
            index
                .classify(&cookie, FileIdentity { dev: 7, ino: 8 })
                .unwrap()
                .kind,
            ProtectedResourceKind::CookieStore
        );
        assert!(index
            .classify(
                &library.join("Application Support/Google/Chrome/Cookies"),
                FileIdentity { dev: 9, ino: 10 },
            )
            .is_none());
        assert!(index
            .namespace_scope(&library.join("Application Support/Google/Chrome"))
            .is_none());
    }

    #[test]
    fn startup_scan_protects_tree_hardlink_alias_outside_profile() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Chrome");
        let storage = root.join("Default/Local Storage/leveldb/000001.ldb");
        std::fs::create_dir_all(storage.parent().unwrap()).unwrap();
        std::fs::write(&storage, b"synthetic web storage").unwrap();
        std::fs::write(root.join("Local State"), b"synthetic state").unwrap();
        let alias = temp.path().join("preexisting-outside-alias");
        std::fs::hard_link(&storage, &alias).unwrap();
        let index = MacResourceIndex::from_browser_enrollments(&[MacBrowserEnrollment {
            browser_id: BrowserId("chrome".into()),
            family: BrowserFamily::Chromium,
            profile_root: root,
            owner_uid: 501,
            app_bundle: None,
            executables: vec![],
        }])
        .unwrap();
        let metadata = std::fs::metadata(&alias).unwrap();
        assert_eq!(
            index
                .classify(
                    &alias,
                    FileIdentity {
                        dev: metadata.dev(),
                        ino: metadata.ino(),
                    },
                )
                .unwrap()
                .kind,
            ProtectedResourceKind::WebStorage
        );
        assert!(!index.alias_saturated());
        assert!(index.alias_count() > 0);
    }

    #[test]
    fn symlink_open_is_protected_by_kernel_observed_target_identity() {
        let temp = tempfile::tempdir().unwrap();
        let protected = temp.path().join("Cookies");
        std::fs::write(&protected, b"synthetic cookie db").unwrap();
        let alias = temp.path().join("symlink-alias");
        std::os::unix::fs::symlink(&protected, &alias).unwrap();
        let mut registry = ProtectedResourceRegistry::new();
        registry.enroll_file(ProtectedResource {
            id: ProtectedResourceId("cookies".into()),
            kind: ProtectedResourceKind::CookieStore,
            owner_uid: 501,
            browser: Some(BrowserId("chrome".into())),
            profile: Some(ProfileId("Default".into())),
            path: protected,
        });
        let index = MacResourceIndex::from_registry(&registry).unwrap();
        // `metadata`, like the ES open target, observes the followed object;
        // `symlink_metadata` would describe only the namespace entry.
        let target = std::fs::metadata(&alias).unwrap();
        assert!(index
            .classify(
                &alias,
                FileIdentity {
                    dev: target.dev(),
                    ino: target.ino(),
                },
            )
            .is_some());
    }

    #[test]
    fn alias_index_has_a_hard_capacity_and_reports_saturation() {
        let mut index = MacResourceIndex {
            alias_capacity: 1,
            ..MacResourceIndex::default()
        };
        let resource = ProtectedResource {
            id: ProtectedResourceId("bounded".into()),
            kind: ProtectedResourceKind::CookieStore,
            owner_uid: 501,
            browser: Some(BrowserId("chrome".into())),
            profile: Some(ProfileId("Default".into())),
            path: std::path::PathBuf::from("/synthetic/Cookies"),
        };
        assert!(index.observe_alias(FileIdentity { dev: 1, ino: 1 }, resource.clone()));
        assert!(!index.observe_alias(FileIdentity { dev: 1, ino: 2 }, resource));
        assert_eq!(index.alias_count(), 1);
        assert!(index.alias_saturated());
    }

    #[test]
    fn ssh_key_is_classified_by_inode_alias_and_enrolled_path_after_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let key = temp.path().join("id_ed25519");
        std::fs::write(&key, b"synthetic ephemeral key").unwrap();
        let key = std::fs::canonicalize(key).unwrap();
        let index = MacResourceIndex::from_enrollments(&[], std::slice::from_ref(&key)).unwrap();
        assert_eq!(index.ssh_key_count(), 1);
        let plan = index.target_selection_plan();
        assert!(plan
            .rules()
            .iter()
            .any(|rule| rule.path == key && !rule.prefix));
        assert!(plan
            .rules()
            .iter()
            .any(|rule| { rule.path == key.parent().unwrap() && !rule.prefix }));

        let alias = temp.path().join("alias");
        std::fs::hard_link(&key, &alias).unwrap();
        let alias_metadata = std::fs::metadata(&alias).unwrap();
        let alias_resource = index
            .classify(
                &alias,
                FileIdentity {
                    dev: alias_metadata.dev(),
                    ino: alias_metadata.ino(),
                },
            )
            .unwrap();
        assert_eq!(alias_resource.kind, ProtectedResourceKind::SshPrivateKey);
        assert_eq!(alias_resource.path, key);

        std::fs::rename(&key, temp.path().join("old-key")).unwrap();
        std::fs::write(&key, b"replacement synthetic key").unwrap();
        let replacement_metadata = std::fs::metadata(&key).unwrap();
        let replacement_resource = index
            .classify(
                &key,
                FileIdentity {
                    dev: replacement_metadata.dev(),
                    ino: replacement_metadata.ino(),
                },
            )
            .unwrap();
        assert_eq!(
            replacement_resource.kind,
            ProtectedResourceKind::SshPrivateKey
        );
        assert!(index.is_configured_ssh_resource(&replacement_resource));
    }

    #[test]
    fn selection_plan_keeps_safari_library_narrow() {
        let temp = tempfile::tempdir().unwrap();
        let library = temp.path().join("Library");
        std::fs::create_dir_all(library.join("Safari")).unwrap();
        let index = MacResourceIndex::from_browser_enrollments(&[MacBrowserEnrollment {
            browser_id: BrowserId("safari".into()),
            family: BrowserFamily::Safari,
            profile_root: library.clone(),
            owner_uid: 501,
            app_bundle: None,
            executables: vec![],
        }])
        .unwrap();
        let plan = index.target_selection_plan();
        assert!(plan
            .rules()
            .iter()
            .any(|rule| rule.path == library.join("Safari") && rule.prefix));
        assert!(!plan
            .rules()
            .iter()
            .any(|rule| rule.path == library && rule.prefix));
    }

    #[test]
    fn unresolved_external_hardlink_is_reported_before_enforcement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Chrome");
        let cookies = root.join("Default/Network/Cookies");
        std::fs::create_dir_all(cookies.parent().unwrap()).unwrap();
        std::fs::write(&cookies, b"synthetic cookie db").unwrap();
        std::fs::write(root.join("Default/Preferences"), b"synthetic").unwrap();
        std::fs::hard_link(&cookies, temp.path().join("outside-alias")).unwrap();
        let index = MacResourceIndex::from_browser_enrollments(&[MacBrowserEnrollment {
            browser_id: BrowserId("chrome".into()),
            family: BrowserFamily::Chromium,
            profile_root: root,
            owner_uid: 501,
            app_bundle: None,
            executables: vec![],
        }])
        .unwrap();
        assert!(index.concrete_count() > 0);
        assert!(index.unresolved_external_hardlink_count() > 0);
    }
}
