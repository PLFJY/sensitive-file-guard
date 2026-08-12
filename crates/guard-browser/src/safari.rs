//! macOS Safari resource classification.
//!
//! Safari keeps browser data in two distinct locations below a user's
//! `~/Library`: the legacy `Safari` directory and its App Sandbox container.
//! The profile root is therefore `~/Library`, but this module classifies only
//! the narrow Safari-relative names below; it never turns the rest of Library
//! into a protected namespace.

use std::path::{Path, PathBuf};

use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};

use crate::registry::TreeRoot;

pub const PROFILE_ID: &str = "(safari)";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    File(ProtectedResourceKind),
    Tree(ProtectedResourceKind),
    None,
}

/// Classify a path relative to `~/Library` without opening its contents.
pub fn classify_library_relative(rel: &Path) -> Classified {
    let components = rel
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let joined = components.join("/");
    match joined.as_str() {
        "Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies" => {
            Classified::File(ProtectedResourceKind::CookieStore)
        }
        "Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db"
        | "Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db-wal"
        | "Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db-shm"
        | "Containers/com.apple.Safari/Data/Library/Safari/CloudTabs.db"
        | "Containers/com.apple.Safari/Data/Library/Safari/CloudTabs.db-wal"
        | "Containers/com.apple.Safari/Data/Library/Safari/CloudTabs.db-shm"
        | "Safari/RecentlyClosedTabs.plist" => {
            Classified::File(ProtectedResourceKind::SessionStore)
        }
        "Safari/History.db" | "Safari/History.db-wal" | "Safari/History.db-shm" => {
            Classified::File(ProtectedResourceKind::History)
        }
        "Containers/com.apple.Safari/Data/Library/HTTPStorages" => {
            Classified::Tree(ProtectedResourceKind::WebStorage)
        }
        "Containers/com.apple.Safari/Data/Library/Safari/WebExtensions" => {
            Classified::Tree(ProtectedResourceKind::WebStorage)
        }
        _ => Classified::None,
    }
}

/// True for only the two Safari-owned Library subtrees. This is used by the
/// macOS namespace gate and deliberately excludes arbitrary `~/Library` paths.
pub fn is_safari_namespace_path(rel: &Path) -> bool {
    rel.starts_with(Path::new("Safari"))
        || rel.starts_with(Path::new("Containers/com.apple.Safari/Data/Library"))
}

/// Discover the fixed, security-relevant Safari paths. No recursive profile
/// walk is performed, keeping enrollment bounded and metadata-only.
pub fn discover(
    browser: &BrowserId,
    library_root: &Path,
    owner_uid: u32,
) -> std::io::Result<(Vec<ProtectedResource>, Vec<TreeRoot>)> {
    let mut files = Vec::new();
    let mut trees = Vec::new();
    for relative in SAFARI_CANDIDATES {
        let path = library_root.join(relative);
        match classify_library_relative(Path::new(relative)) {
            Classified::File(kind) if path.is_file() => {
                files.push(resource(&path, kind, browser, owner_uid))
            }
            Classified::Tree(kind) if path.is_dir() => trees.push(TreeRoot {
                dir: path,
                browser: browser.clone(),
                profile: ProfileId(PROFILE_ID.into()),
                kind,
                owner_uid,
            }),
            _ => {}
        }
    }
    Ok((files, trees))
}

const SAFARI_CANDIDATES: &[&str] = &[
    "Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies",
    "Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db",
    "Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db-wal",
    "Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db-shm",
    "Containers/com.apple.Safari/Data/Library/Safari/CloudTabs.db",
    "Containers/com.apple.Safari/Data/Library/Safari/CloudTabs.db-wal",
    "Containers/com.apple.Safari/Data/Library/Safari/CloudTabs.db-shm",
    "Safari/RecentlyClosedTabs.plist",
    "Safari/History.db",
    "Safari/History.db-wal",
    "Safari/History.db-shm",
    "Containers/com.apple.Safari/Data/Library/HTTPStorages",
    "Containers/com.apple.Safari/Data/Library/Safari/WebExtensions",
];

fn resource(
    path: &Path,
    kind: ProtectedResourceKind,
    browser: &BrowserId,
    owner_uid: u32,
) -> ProtectedResource {
    ProtectedResource {
        id: ProtectedResourceId(path.to_string_lossy().into_owned()),
        kind,
        owner_uid,
        browser: Some(browser.clone()),
        profile: Some(ProfileId(PROFILE_ID.into())),
        path: PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_only_narrow_safari_data_paths() {
        assert_eq!(
            classify_library_relative(Path::new(
                "Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"
            )),
            Classified::File(ProtectedResourceKind::CookieStore)
        );
        assert_eq!(
            classify_library_relative(Path::new(
                "Containers/com.apple.Safari/Data/Library/HTTPStorages"
            )),
            Classified::Tree(ProtectedResourceKind::WebStorage)
        );
        assert_eq!(
            classify_library_relative(Path::new("Application Support/unrelated")),
            Classified::None
        );
    }

    #[test]
    fn namespace_scope_does_not_cover_all_of_library() {
        assert!(is_safari_namespace_path(Path::new("Safari/History.db")));
        assert!(is_safari_namespace_path(Path::new(
            "Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies"
        )));
        assert!(!is_safari_namespace_path(Path::new(
            "Application Support/Google/Chrome"
        )));
    }
}
