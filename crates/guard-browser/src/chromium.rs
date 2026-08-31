//! Chromium-family browser profile discovery and resource classification.
//!
//! Works for Chrome, Chromium, Brave, Edge, Vivaldi: they share the same
//! user-data-dir / profile layout. The `BrowserId` is supplied explicitly by
//! the caller (config enrollment) — discovery never trusts the directory name.

use std::fs;
use std::path::{Path, PathBuf};

use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};
use guard_platform::config::BrowserProtectionLevel;

use crate::registry::TreeRoot;

/// Profile id used for the shared `Local State` key-material file, which is
/// per-user-data-dir rather than per-profile.
pub const LOCAL_STATE_PROFILE: &str = "(local-state)";

/// What a profile-relative path classifies as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    /// A concrete protected file.
    File(ProtectedResourceKind),
    /// A protected directory tree (mark recursively).
    Tree(ProtectedResourceKind),
    /// Not protected.
    None,
}

/// Classify a path relative to the profile directory (e.g. `Network/Cookies`,
/// `Local Storage`, `Login Data`). Pure function, unit-testable without a
/// filesystem.
pub fn classify_profile_relative(rel: &Path, level: BrowserProtectionLevel) -> Classified {
    let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
        return Classified::None;
    };
    // Concrete cookie files under `Network/` (multi-component path).
    if rel.parent() == Some(Path::new("Network"))
        && matches!(
            name,
            "Cookies" | "Cookies-wal" | "Cookies-shm" | "Cookies-journal"
        )
    {
        return protected_file(ProtectedResourceKind::CookieStore, level);
    }
    if rel.parent() != Some(Path::new("")) {
        return Classified::None;
    }
    match name {
        // Profile-root cookie location.
        "Cookies" | "Cookies-wal" | "Cookies-shm" | "Cookies-journal" => {
            protected_file(ProtectedResourceKind::CookieStore, level)
        }
        "Local State" => protected_file(ProtectedResourceKind::BrowserKeyMaterial, level),
        // `Login Data*` includes the SQLite sidecars used by Chromium's saved
        // password store.
        _ if name == "Login Data" || name.starts_with("Login Data") => {
            protected_file(ProtectedResourceKind::SavedCredentials, level)
        }
        "Session Storage" | "Local Storage" | "IndexedDB" => {
            protected_tree(ProtectedResourceKind::WebStorage, level)
        }
        _ => Classified::None,
    }
}

fn protected_file(kind: ProtectedResourceKind, level: BrowserProtectionLevel) -> Classified {
    if level.protects(kind) {
        Classified::File(kind)
    } else {
        Classified::None
    }
}

fn protected_tree(kind: ProtectedResourceKind, level: BrowserProtectionLevel) -> Classified {
    if level.protects(kind) {
        Classified::Tree(kind)
    } else {
        Classified::None
    }
}

/// Discover all protected resources in a Chromium `user_data_dir`.
///
/// Enrolls `Local State` (per user-data-dir) plus every profile subdir.
pub fn discover(
    browser: &BrowserId,
    user_data_dir: &Path,
    owner_uid: u32,
    level: BrowserProtectionLevel,
) -> std::io::Result<(Vec<ProtectedResource>, Vec<TreeRoot>)> {
    let mut files = Vec::new();
    let mut trees = Vec::new();

    // Local State holds the os_crypt encrypted_key for cookie decryption.
    let local_state = user_data_dir.join("Local State");
    if local_state.is_file() {
        files.push(resource(
            &local_state,
            ProtectedResourceKind::BrowserKeyMaterial,
            browser,
            LOCAL_STATE_PROFILE,
            owner_uid,
        ));
    }

    for entry in fs::read_dir(user_data_dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let profile_dir = entry.path();
        if is_chromium_profile(&profile_dir) {
            let profile_id = entry.file_name().to_string_lossy().into_owned();
            discover_profile(
                browser,
                &profile_id,
                &profile_dir,
                owner_uid,
                level,
                &mut files,
                &mut trees,
            );
        }
    }
    Ok((files, trees))
}

/// True if `dir` looks like a Chromium profile dir (contains a cookie store or
/// `Preferences`). This keeps `Snapshots`/`System Profile`/etc. out of profile
/// discovery.
fn is_chromium_profile(dir: &Path) -> bool {
    dir.join("Network").join("Cookies").is_file()
        || dir.join("Cookies").is_file()
        || dir.join("Preferences").is_file()
}

/// Discover resources within a single Chromium profile dir.
fn discover_profile(
    browser: &BrowserId,
    profile_id: &str,
    profile_dir: &Path,
    owner_uid: u32,
    level: BrowserProtectionLevel,
    files: &mut Vec<ProtectedResource>,
    trees: &mut Vec<TreeRoot>,
) {
    let profile = ProfileId(profile_id.to_string());
    // Walk the profile dir one level deep; descend into `Network` to catch the
    // cookie sidecars. Tree dirs are enrolled as TreeRoots without enumerating
    // their descendants (the registry prefix-matches any descendant).
    let mut stack: Vec<PathBuf> = vec![profile_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let rel = path.strip_prefix(profile_dir).unwrap_or(&path);
            match classify_profile_relative(rel, level) {
                Classified::File(kind) => {
                    if ft.is_file() {
                        files.push(resource(&path, kind, browser, profile_id, owner_uid));
                    }
                }
                Classified::Tree(kind) => {
                    if ft.is_dir() {
                        trees.push(TreeRoot {
                            dir: path,
                            browser: browser.clone(),
                            profile: profile.clone(),
                            kind,
                            owner_uid,
                        });
                    }
                }
                Classified::None => {
                    // Descend into `Network` to find cookie sidecars; don't
                    // recurse into arbitrary subdirs (keeps discovery bounded).
                    if ft.is_dir() && rel == Path::new("Network") {
                        stack.push(path);
                    }
                }
            }
        }
    }
}

fn resource(
    path: &Path,
    kind: ProtectedResourceKind,
    browser: &BrowserId,
    profile_id: &str,
    owner_uid: u32,
) -> ProtectedResource {
    ProtectedResource {
        id: ProtectedResourceId(path.to_string_lossy().into_owned()),
        kind,
        owner_uid,
        browser: Some(browser.clone()),
        profile: Some(ProfileId(profile_id.to_string())),
        path: path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_test_fixtures::chromium::ChromiumProfile;

    // --- pure classifier ---

    #[test]
    fn classify_cookie_sidecars() {
        for path in [
            "Network/Cookies",
            "Network/Cookies-wal",
            "Network/Cookies-shm",
            "Network/Cookies-journal",
        ] {
            assert_eq!(
                classify_profile_relative(Path::new(path), BrowserProtectionLevel::Common),
                Classified::File(ProtectedResourceKind::CookieStore),
                "{path}"
            );
        }
    }

    #[test]
    fn classify_profile_root_cookies() {
        assert_eq!(
            classify_profile_relative(Path::new("Cookies"), BrowserProtectionLevel::Common),
            Classified::File(ProtectedResourceKind::CookieStore)
        );
    }

    #[test]
    fn classify_local_state_key_material() {
        assert_eq!(
            classify_profile_relative(Path::new("Local State"), BrowserProtectionLevel::Common),
            Classified::File(ProtectedResourceKind::BrowserKeyMaterial)
        );
    }

    #[test]
    fn common_classifies_saved_credentials() {
        assert_eq!(
            classify_profile_relative(Path::new("Login Data"), BrowserProtectionLevel::Common),
            Classified::File(ProtectedResourceKind::SavedCredentials)
        );
        assert_eq!(
            classify_profile_relative(
                Path::new("Login Data-journal"),
                BrowserProtectionLevel::Common
            ),
            Classified::File(ProtectedResourceKind::SavedCredentials)
        );
    }

    #[test]
    fn strict_classifies_authentication_capable_storage_only() {
        assert_eq!(
            classify_profile_relative(Path::new("Session Storage"), BrowserProtectionLevel::Strict),
            Classified::Tree(ProtectedResourceKind::WebStorage)
        );
        assert_eq!(
            classify_profile_relative(Path::new("Local Storage"), BrowserProtectionLevel::Strict),
            Classified::Tree(ProtectedResourceKind::WebStorage)
        );
        assert_eq!(
            classify_profile_relative(Path::new("IndexedDB"), BrowserProtectionLevel::Strict),
            Classified::Tree(ProtectedResourceKind::WebStorage)
        );
    }

    #[test]
    fn common_excludes_web_storage() {
        for path in ["Session Storage", "Local Storage", "IndexedDB"] {
            assert_eq!(
                classify_profile_relative(Path::new(path), BrowserProtectionLevel::Common),
                Classified::None,
                "{path}"
            );
        }
    }

    #[test]
    fn all_levels_exclude_noncredential_profile_state() {
        for level in [
            BrowserProtectionLevel::Common,
            BrowserProtectionLevel::Strict,
        ] {
            for path in ["Sessions", "History", "Bookmarks", "Web Data", "README"] {
                assert_eq!(
                    classify_profile_relative(Path::new(path), level),
                    Classified::None,
                    "{level:?}: {path}"
                );
            }
        }
    }

    // --- discovery against synthetic fixtures (no real profiles) ---

    #[test]
    fn discover_synthetic_chromium_profile() {
        let p = ChromiumProfile::create("Default").expect("create fixture");
        let browser = BrowserId("chrome".into());
        let (files, trees) = discover(
            &browser,
            &p.user_data_dir,
            1000,
            BrowserProtectionLevel::Strict,
        )
        .expect("discover");

        assert!(files.len() >= 5, "got {} files", files.len());
        let kinds: Vec<_> = files.iter().map(|r| r.kind).collect();
        assert!(kinds.contains(&ProtectedResourceKind::BrowserKeyMaterial));
        assert!(kinds.contains(&ProtectedResourceKind::CookieStore));
        assert!(kinds.contains(&ProtectedResourceKind::SavedCredentials));

        // cookie sidecars present
        let cookie_count = files
            .iter()
            .filter(|r| r.kind == ProtectedResourceKind::CookieStore)
            .count();
        assert_eq!(cookie_count, 3, "Cookies + wal + shm");

        assert!(!files.iter().any(|resource| resource.path == p.web_data));

        let tree_kinds: Vec<_> = trees.iter().map(|t| t.kind).collect();
        assert!(tree_kinds.contains(&ProtectedResourceKind::WebStorage));
        assert!(!trees.iter().any(|tree| tree.dir == p.sessions_dir));

        // every resource is owned by the synthetic browser
        assert!(files.iter().all(|r| r.browser.as_ref() == Some(&browser)));
    }

    #[test]
    fn discover_multiple_chromium_profiles() {
        let p = ChromiumProfile::create("Default").expect("create fixture");
        // add a second profile under the same user_data_dir
        let profile2 = p.user_data_dir.join("Profile 1");
        fs::create_dir_all(profile2.join("Network")).unwrap();
        fs::write(profile2.join("Network").join("Cookies"), b"synthetic").unwrap();

        let browser = BrowserId("chrome".into());
        let (files, _trees) = discover(
            &browser,
            &p.user_data_dir,
            1000,
            BrowserProtectionLevel::Common,
        )
        .expect("discover");
        let profiles: std::collections::HashSet<_> = files
            .iter()
            .filter_map(|r| r.profile.as_ref().map(|p| p.0.clone()))
            .collect();
        assert!(profiles.contains("Default"));
        assert!(profiles.contains("Profile 1"));
    }

    #[test]
    fn discover_does_not_touch_real_profiles() {
        // Sanity: discovery only reads the supplied dir. Using a synthetic temp
        // dir proves no developer real profile is enumerated.
        let p = ChromiumProfile::create("Default").expect("create fixture");
        let browser = BrowserId("chrome".into());
        let (files, _) = discover(
            &browser,
            &p.user_data_dir,
            1000,
            BrowserProtectionLevel::Common,
        )
        .expect("discover");
        for r in &files {
            assert!(r.path.starts_with(&p.user_data_dir));
        }
    }
}
