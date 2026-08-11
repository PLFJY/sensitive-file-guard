//! Protected-resource registry.
//!
//! Holds the set of discovered protected resources and answers the hot-path
//! question: "is this opened path protected, and if so, which resource?".
//!
//! Two kinds of entries:
//! - **Concrete files** (critical files like `Cookies`, `Login Data`, `key4.db`)
//!   are enrolled individually and matched by exact canonical path. This gives
//!   precise, file-identity-anchored protection for the highest-value targets.
//! - **Directory trees** (`Sessions/`, `Local Storage/`, `storage/`, ...) are
//!   enrolled as `TreeRoot`s and matched by path prefix, so a file created
//!   inside the tree after discovery is still classified as protected without
//!   re-scanning on every open. The platform mediator marks these tree
//!   dirs recursively; the recursive-mark race is documented there.
//!
//! No permanent trust is granted merely because a path is called "Chrome":
//! discovery is driven by explicit `BrowserId`/family enrollment from config,
//! not by path name.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};

/// A directory tree whose every descendant file is protected with `kind`.
#[derive(Debug, Clone)]
pub struct TreeRoot {
    pub dir: PathBuf,
    pub browser: BrowserId,
    pub profile: ProfileId,
    pub kind: ProtectedResourceKind,
    pub owner_uid: u32,
}

impl TreeRoot {
    /// Synthesize a `ProtectedResource` for a concrete file under this tree.
    fn resource_for(&self, path: PathBuf) -> ProtectedResource {
        ProtectedResource {
            id: ProtectedResourceId(path.to_string_lossy().into_owned()),
            kind: self.kind,
            owner_uid: self.owner_uid,
            browser: Some(self.browser.clone()),
            profile: Some(self.profile.clone()),
            path,
        }
    }
}

#[derive(Debug, Default)]
pub struct ProtectedResourceRegistry {
    /// Canonical path -> concrete resource (critical files).
    files: HashMap<PathBuf, ProtectedResource>,
    /// Protected directory trees, prefix-matched.
    trees: Vec<TreeRoot>,
}

impl ProtectedResourceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enroll a concrete file resource. If a resource at the same canonical path
    /// already exists, it is replaced.
    pub fn enroll_file(&mut self, resource: ProtectedResource) {
        self.files.insert(resource.path.clone(), resource);
    }

    /// Enroll a protected directory tree. Descendant files are classified with
    /// the tree's `kind`/`browser`/`profile`/`owner_uid`.
    pub fn enroll_tree(&mut self, tree: TreeRoot) {
        self.trees.push(tree);
    }

    /// Number of enrolled concrete file resources.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Iterate all enrolled concrete file resources.
    pub fn files(&self) -> impl Iterator<Item = &ProtectedResource> {
        self.files.values()
    }

    /// Iterate all enrolled tree roots.
    pub fn trees(&self) -> &[TreeRoot] {
        &self.trees
    }

    /// Hot-path classification. Returns the protected resource for `path`, or
    /// `None` if the path is not protected. Canonicalizes the path when possible
    /// so that symlinks/relative paths still match.
    pub fn classify(&self, path: &Path) -> Option<ProtectedResource> {
        let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

        if let Some(res) = self.files.get(&canon) {
            return Some(res.clone());
        }
        // Also try the original (non-canonical) path in case canonicalize
        // failed or differs from enrollment (enrollment canonicalized).
        if canon != path {
            if let Some(res) = self.files.get(path) {
                return Some(res.clone());
            }
        }
        for tree in &self.trees {
            if canon.starts_with(&tree.dir) {
                return Some(tree.resource_for(canon));
            }
            if canon != path && path.starts_with(&tree.dir) {
                return Some(tree.resource_for(path.to_path_buf()));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_resource(
        path: &str,
        kind: ProtectedResourceKind,
        browser: &str,
        profile: &str,
    ) -> ProtectedResource {
        ProtectedResource {
            id: ProtectedResourceId(path.into()),
            kind,
            owner_uid: 1000,
            browser: Some(BrowserId(browser.into())),
            profile: Some(ProfileId(profile.into())),
            path: PathBuf::from(path),
        }
    }

    #[test]
    fn classify_unprotected_path_returns_none() {
        let reg = ProtectedResourceRegistry::new();
        assert!(reg.classify(Path::new("/tmp/ordinary.txt")).is_none());
    }

    #[test]
    fn classify_enrolled_file_returns_resource() {
        let mut reg = ProtectedResourceRegistry::new();
        let r = file_resource(
            "/home/u/chrome/Default/Network/Cookies",
            ProtectedResourceKind::CookieStore,
            "chrome",
            "Default",
        );
        reg.enroll_file(r.clone());
        let got = reg
            .classify(Path::new("/home/u/chrome/Default/Network/Cookies"))
            .expect("found");
        assert_eq!(got.kind, ProtectedResourceKind::CookieStore);
        assert_eq!(got.browser.as_ref().unwrap().0, "chrome");
        assert_eq!(got.profile.as_ref().unwrap().0, "Default");
    }

    #[test]
    fn classify_tree_descendant_synthesizes_resource() {
        let mut reg = ProtectedResourceRegistry::new();
        reg.enroll_tree(TreeRoot {
            dir: PathBuf::from("/home/u/chrome/Default/Local Storage"),
            browser: BrowserId("chrome".into()),
            profile: ProfileId("Default".into()),
            kind: ProtectedResourceKind::WebStorage,
            owner_uid: 1000,
        });
        // A file that was never explicitly enrolled but lives under the tree.
        let got = reg
            .classify(Path::new(
                "/home/u/chrome/Default/Local Storage/https_example.com_0.localstorage",
            ))
            .expect("tree descendant is protected");
        assert_eq!(got.kind, ProtectedResourceKind::WebStorage);
        assert_eq!(got.browser.as_ref().unwrap().0, "chrome");
    }
}
