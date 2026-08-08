//! Firefox (and Firefox-derived, e.g. Zen) profile discovery and resource
//! classification. The `BrowserId` is supplied explicitly by the caller.

use std::fs;
use std::path::{Path, PathBuf};

use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};

use crate::registry::TreeRoot;

/// What a profile-relative path classifies as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    File(ProtectedResourceKind),
    Tree(ProtectedResourceKind),
    None,
}

/// Classify a path relative to a Firefox profile dir. Pure / unit-testable.
pub fn classify_profile_relative(rel: &Path) -> Classified {
    let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
        return Classified::None;
    };
    match name {
        "cookies.sqlite" | "cookies.sqlite-wal" | "cookies.sqlite-shm" => {
            Classified::File(ProtectedResourceKind::CookieStore)
        }
        "logins.json" => Classified::File(ProtectedResourceKind::SavedCredentials),
        "key4.db" => Classified::File(ProtectedResourceKind::BrowserKeyMaterial),
        "sessionstore-backups" => Classified::Tree(ProtectedResourceKind::SessionStore),
        "storage" => Classified::Tree(ProtectedResourceKind::WebStorage),
        _ => Classified::None,
    }
}

/// Discover Firefox profiles under `root`.
///
/// If `root` itself contains `cookies.sqlite`, it is treated as a single
/// profile dir. Otherwise each subdir of `root` that contains `cookies.sqlite`
/// is treated as a profile dir (the standard `~/.mozilla/firefox/` layout).
pub fn discover(
    browser: &BrowserId,
    root: &Path,
    owner_uid: u32,
) -> std::io::Result<(Vec<ProtectedResource>, Vec<TreeRoot>)> {
    let mut files = Vec::new();
    let mut trees = Vec::new();

    let profiles: Vec<PathBuf> = if root.join("cookies.sqlite").is_file() {
        vec![root.to_path_buf()]
    } else {
        let mut out = Vec::new();
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let dir = entry.path();
            if dir.join("cookies.sqlite").is_file() {
                out.push(dir);
            }
        }
        out
    };

    for profile_dir in profiles {
        let profile_id = profile_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "profile".into());
        discover_profile(
            browser,
            &profile_id,
            &profile_dir,
            owner_uid,
            &mut files,
            &mut trees,
        );
    }
    Ok((files, trees))
}

fn discover_profile(
    browser: &BrowserId,
    profile_id: &str,
    profile_dir: &Path,
    owner_uid: u32,
    files: &mut Vec<ProtectedResource>,
    trees: &mut Vec<TreeRoot>,
) {
    let profile = ProfileId(profile_id.to_string());
    let Ok(entries) = fs::read_dir(profile_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else {
            continue;
        };
        let rel = path.strip_prefix(profile_dir).unwrap_or(&path);
        match classify_profile_relative(rel) {
            Classified::File(kind) => {
                if ft.is_file() {
                    files.push(resource(&path, kind, browser, &profile, owner_uid));
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
            Classified::None => {}
        }
    }
}

fn resource(
    path: &Path,
    kind: ProtectedResourceKind,
    browser: &BrowserId,
    profile: &ProfileId,
    owner_uid: u32,
) -> ProtectedResource {
    ProtectedResource {
        id: ProtectedResourceId(path.to_string_lossy().into_owned()),
        kind,
        owner_uid,
        browser: Some(browser.clone()),
        profile: Some(profile.clone()),
        path: path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_test_fixtures::firefox::FirefoxProfile;

    #[test]
    fn classify_cookie_sidecars() {
        assert_eq!(
            classify_profile_relative(Path::new("cookies.sqlite")),
            Classified::File(ProtectedResourceKind::CookieStore)
        );
        assert_eq!(
            classify_profile_relative(Path::new("cookies.sqlite-wal")),
            Classified::File(ProtectedResourceKind::CookieStore)
        );
        assert_eq!(
            classify_profile_relative(Path::new("cookies.sqlite-shm")),
            Classified::File(ProtectedResourceKind::CookieStore)
        );
    }

    #[test]
    fn classify_logins_and_keymaterial() {
        assert_eq!(
            classify_profile_relative(Path::new("logins.json")),
            Classified::File(ProtectedResourceKind::SavedCredentials)
        );
        assert_eq!(
            classify_profile_relative(Path::new("key4.db")),
            Classified::File(ProtectedResourceKind::BrowserKeyMaterial)
        );
    }

    #[test]
    fn classify_session_and_storage_trees() {
        assert_eq!(
            classify_profile_relative(Path::new("sessionstore-backups")),
            Classified::Tree(ProtectedResourceKind::SessionStore)
        );
        assert_eq!(
            classify_profile_relative(Path::new("storage")),
            Classified::Tree(ProtectedResourceKind::WebStorage)
        );
    }

    #[test]
    fn classify_unrelated_is_none() {
        assert_eq!(
            classify_profile_relative(Path::new("prefs.js")),
            Classified::None
        );
        assert_eq!(
            classify_profile_relative(Path::new("places.sqlite")),
            Classified::None
        );
    }

    #[test]
    fn discover_synthetic_firefox_profile() {
        let p = FirefoxProfile::create("test-profile").expect("create fixture");
        let browser = BrowserId("firefox".into());
        let (files, trees) = discover(&browser, &p.profile_dir, 1000).expect("discover");

        let kinds: Vec<_> = files.iter().map(|r| r.kind).collect();
        assert!(kinds.contains(&ProtectedResourceKind::CookieStore));
        assert!(kinds.contains(&ProtectedResourceKind::SavedCredentials));
        assert!(kinds.contains(&ProtectedResourceKind::BrowserKeyMaterial));

        // cookies.sqlite + wal => 2 cookie resources
        let cookie_count = files
            .iter()
            .filter(|r| r.kind == ProtectedResourceKind::CookieStore)
            .count();
        assert_eq!(cookie_count, 2);

        let tree_kinds: Vec<_> = trees.iter().map(|t| t.kind).collect();
        assert!(tree_kinds.contains(&ProtectedResourceKind::SessionStore));
        assert!(tree_kinds.contains(&ProtectedResourceKind::WebStorage));

        assert!(files.iter().all(|r| r.browser.as_ref() == Some(&browser)));
    }

    #[test]
    fn discover_multiple_firefox_profiles() {
        let p = FirefoxProfile::create("profile-a").expect("create fixture");
        // second profile under the same root (the temp dir)
        let profile_b = p.root_path().join("profile-b");
        fs::create_dir_all(&profile_b).unwrap();
        fs::write(profile_b.join("cookies.sqlite"), b"synthetic").unwrap();

        let browser = BrowserId("firefox".into());
        let (files, _) = discover(&browser, p.root_path(), 1000).expect("discover");
        let profiles: std::collections::HashSet<_> = files
            .iter()
            .filter_map(|r| r.profile.as_ref().map(|p| p.0.clone()))
            .collect();
        assert!(profiles.contains("profile-a"));
        assert!(profiles.contains("profile-b"));
    }

    #[test]
    fn discover_does_not_touch_real_profiles() {
        let p = FirefoxProfile::create("test-profile").expect("create fixture");
        let browser = BrowserId("firefox".into());
        let (files, _) = discover(&browser, p.root_path(), 1000).expect("discover");
        for r in &files {
            assert!(r.path.starts_with(p.root_path()));
        }
    }
}
