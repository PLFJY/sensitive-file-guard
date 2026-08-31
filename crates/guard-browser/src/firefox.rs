//! Firefox (and Firefox-derived, e.g. Zen) profile discovery and resource
//! classification. The `BrowserId` is supplied explicitly by the caller.

use std::fs;
use std::path::{Path, PathBuf};

use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};
use guard_platform::config::BrowserProtectionLevel;

use crate::registry::TreeRoot;

/// What a profile-relative path classifies as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    File(ProtectedResourceKind),
    Tree(ProtectedResourceKind),
    None,
}

/// Classify a path relative to a Firefox profile dir. Pure / unit-testable.
pub fn classify_profile_relative(rel: &Path, level: BrowserProtectionLevel) -> Classified {
    let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
        return Classified::None;
    };
    if rel.parent() != Some(Path::new("")) {
        return Classified::None;
    }
    match name {
        "cookies.sqlite"
        | "cookies.sqlite-wal"
        | "cookies.sqlite-shm"
        | "cookies.sqlite-journal" => protected_file(ProtectedResourceKind::CookieStore, level),
        "logins.json" => protected_file(ProtectedResourceKind::SavedCredentials, level),
        "key4.db" => protected_file(ProtectedResourceKind::BrowserKeyMaterial, level),
        "webappsstore.sqlite"
        | "webappsstore.sqlite-wal"
        | "webappsstore.sqlite-shm"
        | "webappsstore.sqlite-journal" => protected_file(ProtectedResourceKind::WebStorage, level),
        "storage" => protected_tree(ProtectedResourceKind::WebStorage, level),
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

/// Discover Firefox profiles under `root`.
///
/// If `root` itself contains `cookies.sqlite`, it is treated as a single
/// profile dir. Otherwise each subdir of `root` that contains `cookies.sqlite`
/// is treated as a profile dir (the standard `~/.mozilla/firefox/` layout).
pub fn discover(
    browser: &BrowserId,
    root: &Path,
    owner_uid: u32,
    level: BrowserProtectionLevel,
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
            level,
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
    level: BrowserProtectionLevel,
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
        match classify_profile_relative(rel, level) {
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
    fn common_classifies_credential_resources() {
        for (path, kind) in [
            ("cookies.sqlite", ProtectedResourceKind::CookieStore),
            ("cookies.sqlite-wal", ProtectedResourceKind::CookieStore),
            ("cookies.sqlite-shm", ProtectedResourceKind::CookieStore),
            ("cookies.sqlite-journal", ProtectedResourceKind::CookieStore),
            ("logins.json", ProtectedResourceKind::SavedCredentials),
            ("key4.db", ProtectedResourceKind::BrowserKeyMaterial),
        ] {
            assert_eq!(
                classify_profile_relative(Path::new(path), BrowserProtectionLevel::Common),
                Classified::File(kind),
                "{path}"
            );
        }
    }

    #[test]
    fn strict_classifies_authentication_capable_web_storage() {
        assert_eq!(
            classify_profile_relative(Path::new("storage"), BrowserProtectionLevel::Strict),
            Classified::Tree(ProtectedResourceKind::WebStorage)
        );
        for path in [
            "webappsstore.sqlite",
            "webappsstore.sqlite-wal",
            "webappsstore.sqlite-shm",
            "webappsstore.sqlite-journal",
        ] {
            assert_eq!(
                classify_profile_relative(Path::new(path), BrowserProtectionLevel::Strict),
                Classified::File(ProtectedResourceKind::WebStorage),
                "{path}"
            );
        }
    }

    #[test]
    fn common_and_strict_exclude_navigation_state() {
        for level in [
            BrowserProtectionLevel::Common,
            BrowserProtectionLevel::Strict,
        ] {
            for path in ["sessionstore-backups", "places.sqlite", "prefs.js"] {
                assert_eq!(
                    classify_profile_relative(Path::new(path), level),
                    Classified::None,
                    "{path}"
                );
            }
        }
        for path in ["storage", "webappsstore.sqlite"] {
            assert_eq!(
                classify_profile_relative(Path::new(path), BrowserProtectionLevel::Common),
                Classified::None,
                "{path}"
            );
        }
    }

    #[test]
    fn discover_synthetic_firefox_profile() {
        let p = FirefoxProfile::create("test-profile").expect("create fixture");
        let browser = BrowserId("firefox".into());
        let (files, trees) = discover(
            &browser,
            &p.profile_dir,
            1000,
            BrowserProtectionLevel::Strict,
        )
        .expect("discover");

        let kinds: Vec<_> = files.iter().map(|r| r.kind).collect();
        assert!(kinds.contains(&ProtectedResourceKind::CookieStore));
        assert!(kinds.contains(&ProtectedResourceKind::SavedCredentials));
        assert!(kinds.contains(&ProtectedResourceKind::BrowserKeyMaterial));
        assert!(files.iter().any(|resource| {
            resource.kind == ProtectedResourceKind::WebStorage
                && resource.path == p.webappsstore_sqlite
        }));

        // cookies.sqlite + wal => 2 cookie resources
        let cookie_count = files
            .iter()
            .filter(|r| r.kind == ProtectedResourceKind::CookieStore)
            .count();
        assert_eq!(cookie_count, 2);

        let tree_kinds: Vec<_> = trees.iter().map(|t| t.kind).collect();
        assert!(tree_kinds.contains(&ProtectedResourceKind::WebStorage));
        assert!(!trees
            .iter()
            .any(|tree| tree.dir == p.sessionstore_backups_dir));

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
        let (files, _) = discover(
            &browser,
            p.root_path(),
            1000,
            BrowserProtectionLevel::Common,
        )
        .expect("discover");
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
        let (files, _) = discover(
            &browser,
            p.root_path(),
            1000,
            BrowserProtectionLevel::Common,
        )
        .expect("discover");
        for r in &files {
            assert!(r.path.starts_with(p.root_path()));
        }
    }
}
