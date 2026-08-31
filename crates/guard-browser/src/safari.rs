//! macOS Safari credential-resource classification.
//!
//! Safari's profile root is `~/Library`. Classification is limited to its
//! cookie stores and WebKit website-origin storage inside the Safari sandbox.

use std::fs;
use std::path::{Path, PathBuf};

use guard_core::resource::{
    BrowserId, ProfileId, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};
use guard_platform::config::BrowserProtectionLevel;

use crate::registry::TreeRoot;

pub const PROFILE_ID: &str = "(safari)";

const DEFAULT_COOKIE: &str =
    "Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies";
const FALLBACK_COOKIE: &str = "Cookies/Cookies.binarycookies";
const DEFAULT_WEBSITE_DATA: &str =
    "Containers/com.apple.Safari/Data/Library/WebKit/WebsiteData/Default";
const NAMED_WEBSITE_DATA_STORES: &str =
    "Containers/com.apple.Safari/Data/Library/WebKit/WebsiteDataStore";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classified {
    File(ProtectedResourceKind),
    Tree(ProtectedResourceKind),
    None,
}

/// Classify a path relative to `~/Library` without opening its contents.
pub fn classify_library_relative(rel: &Path, level: BrowserProtectionLevel) -> Classified {
    if rel == Path::new(DEFAULT_COOKIE) || rel == Path::new(FALLBACK_COOKIE) {
        return protected_file(ProtectedResourceKind::CookieStore, level);
    }
    if rel == Path::new(DEFAULT_WEBSITE_DATA) {
        return protected_tree(ProtectedResourceKind::WebStorage, level);
    }
    let Ok(named_relative) = rel.strip_prefix(NAMED_WEBSITE_DATA_STORES) else {
        return Classified::None;
    };
    let components = named_relative
        .components()
        .map(|component| component.as_os_str())
        .collect::<Vec<_>>();
    match components.as_slice() {
        [_, cookies, file] if *cookies == "Cookies" && *file == "Cookies.binarycookies" => {
            protected_file(ProtectedResourceKind::CookieStore, level)
        }
        [_, origins] if *origins == "Origins" => {
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

/// True only for Safari namespaces that may contain protected resources.
pub fn is_safari_namespace_path(rel: &Path) -> bool {
    rel == Path::new(FALLBACK_COOKIE)
        || rel.starts_with(Path::new(DEFAULT_COOKIE).parent().expect("cookie parent"))
        || rel.starts_with(Path::new(DEFAULT_WEBSITE_DATA))
        || rel.starts_with(Path::new(NAMED_WEBSITE_DATA_STORES))
}

/// Discover Safari cookie stores and website-origin storage using bounded,
/// metadata-only directory enumeration.
pub fn discover(
    browser: &BrowserId,
    library_root: &Path,
    owner_uid: u32,
    level: BrowserProtectionLevel,
) -> std::io::Result<(Vec<ProtectedResource>, Vec<TreeRoot>)> {
    let mut files = Vec::new();
    let mut trees = Vec::new();

    for relative in [DEFAULT_COOKIE, FALLBACK_COOKIE] {
        enroll_candidate(
            browser,
            library_root,
            owner_uid,
            level,
            relative,
            &mut files,
            &mut trees,
        );
    }
    enroll_candidate(
        browser,
        library_root,
        owner_uid,
        level,
        DEFAULT_WEBSITE_DATA,
        &mut files,
        &mut trees,
    );

    let stores = library_root.join(NAMED_WEBSITE_DATA_STORES);
    if let Ok(entries) = fs::read_dir(stores) {
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                continue;
            }
            let store = entry.file_name().to_string_lossy().into_owned();
            for suffix in ["Cookies/Cookies.binarycookies", "Origins"] {
                let relative = format!("{NAMED_WEBSITE_DATA_STORES}/{store}/{suffix}");
                enroll_candidate(
                    browser,
                    library_root,
                    owner_uid,
                    level,
                    &relative,
                    &mut files,
                    &mut trees,
                );
            }
        }
    }
    Ok((files, trees))
}

fn enroll_candidate(
    browser: &BrowserId,
    library_root: &Path,
    owner_uid: u32,
    level: BrowserProtectionLevel,
    relative: &str,
    files: &mut Vec<ProtectedResource>,
    trees: &mut Vec<TreeRoot>,
) {
    let path = library_root.join(relative);
    match classify_library_relative(Path::new(relative), level) {
        Classified::File(kind) if path.is_file() => {
            files.push(resource(&path, kind, browser, owner_uid));
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
    fn common_classifies_cookie_stores_only() {
        for path in [DEFAULT_COOKIE, FALLBACK_COOKIE] {
            assert_eq!(
                classify_library_relative(Path::new(path), BrowserProtectionLevel::Common),
                Classified::File(ProtectedResourceKind::CookieStore)
            );
        }
        assert_eq!(
            classify_library_relative(
                Path::new(DEFAULT_WEBSITE_DATA),
                BrowserProtectionLevel::Common
            ),
            Classified::None
        );
    }

    #[test]
    fn strict_classifies_default_and_named_origin_storage() {
        for path in [
            DEFAULT_WEBSITE_DATA,
            "Containers/com.apple.Safari/Data/Library/WebKit/WebsiteDataStore/01234567-89ab-cdef-0123-456789abcdef/Origins",
        ] {
            assert_eq!(
                classify_library_relative(Path::new(path), BrowserProtectionLevel::Strict),
                Classified::Tree(ProtectedResourceKind::WebStorage),
                "{path}"
            );
        }
    }

    #[test]
    fn all_levels_exclude_noncredential_safari_state() {
        for level in [
            BrowserProtectionLevel::Common,
            BrowserProtectionLevel::Strict,
        ] {
            for path in [
                "Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db",
                "Containers/com.apple.Safari/Data/Library/Safari/CloudTabs.db",
                "Safari/RecentlyClosedTabs.plist",
                "Safari/History.db",
                "Safari/Bookmarks.plist",
                "Containers/com.apple.Safari/Data/Library/HTTPStorages",
                "Containers/com.apple.Safari/Data/Library/Safari/WebExtensions",
            ] {
                assert_eq!(
                    classify_library_relative(Path::new(path), level),
                    Classified::None,
                    "{path}"
                );
            }
        }
    }

    #[test]
    fn namespace_scope_is_limited_to_credential_locations() {
        assert!(is_safari_namespace_path(Path::new(DEFAULT_COOKIE)));
        assert!(is_safari_namespace_path(Path::new(DEFAULT_WEBSITE_DATA)));
        assert!(!is_safari_namespace_path(Path::new("Safari/History.db")));
        assert!(!is_safari_namespace_path(Path::new(
            "Application Support/Google/Chrome"
        )));
    }
}
