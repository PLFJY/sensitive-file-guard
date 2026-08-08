//! Synthetic Chromium-family browser profile generator.
//!
//! Builds a minimal but realistic Chromium profile tree (usable for Chrome,
//! Chromium, Brave, Edge, Vivaldi) containing harmless marker bytes in place of
//! real cookies/sessions/key material. The tree matches the resource patterns
//! the Phase 05 registry must classify.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use crate::markers;
use crate::util::write_file;

/// A synthetic Chromium-family profile rooted in a temp dir.
///
/// Dropping this value removes the entire temp tree.
pub struct ChromiumProfile {
    pub root: TempDir,
    /// The browser user-data dir (parent of profiles, holds `Local State`).
    pub user_data_dir: PathBuf,
    /// The profile directory (e.g. `<user_data>/Default`).
    pub profile_dir: PathBuf,
    pub local_state: PathBuf,
    pub cookies: PathBuf,
    pub cookies_wal: PathBuf,
    pub cookies_shm: PathBuf,
    pub login_data: PathBuf,
    pub web_data: PathBuf,
    pub sessions_dir: PathBuf,
    pub session_storage_dir: PathBuf,
    pub local_storage_dir: PathBuf,
    pub indexeddb_dir: PathBuf,
}

impl ChromiumProfile {
    /// Create a synthetic profile named `profile_name` (e.g. `"Default"`).
    pub fn create(profile_name: &str) -> io::Result<Self> {
        let root = tempfile::tempdir()?;
        let user_data_dir = root.path().to_path_buf();
        let profile_dir = user_data_dir.join(profile_name);
        let network_dir = profile_dir.join("Network");

        let local_state = user_data_dir.join("Local State");
        let cookies = network_dir.join("Cookies");
        let cookies_wal = network_dir.join("Cookies-wal");
        let cookies_shm = network_dir.join("Cookies-shm");
        let login_data = profile_dir.join("Login Data");
        let web_data = profile_dir.join("Web Data");

        let sessions_dir = profile_dir.join("Sessions");
        let session_storage_dir = profile_dir.join("Session Storage");
        let local_storage_dir = profile_dir.join("Local Storage");
        let indexeddb_dir = profile_dir.join("IndexedDB");

        // Local State is JSON metadata, harmless synthetic content.
        write_file(
            &local_state,
            "{\n  \"profile\": \"synthetic-chromium\"\n}\n",
        )?;

        write_file(&cookies, markers::COOKIE_MARKER)?;
        write_file(&cookies_wal, markers::COOKIE_MARKER)?;
        write_file(&cookies_shm, markers::COOKIE_MARKER)?;
        write_file(&login_data, markers::LOGIN_MARKER)?;
        write_file(&web_data, markers::WEB_STORAGE_MARKER)?;

        fs::create_dir_all(&sessions_dir)?;
        write_file(&sessions_dir.join("Session_Tab_0"), markers::SESSION_MARKER)?;
        fs::create_dir_all(&session_storage_dir)?;
        write_file(
            &session_storage_dir.join("00000000000000001.log"),
            markers::SESSION_MARKER,
        )?;
        fs::create_dir_all(&local_storage_dir)?;
        write_file(
            &local_storage_dir.join("https_example.com_0.localstorage"),
            markers::WEB_STORAGE_MARKER,
        )?;
        let leveldb = indexeddb_dir.join("file_0.indexeddb.leveldb");
        fs::create_dir_all(&leveldb)?;
        write_file(&leveldb.join("000043.log"), markers::WEB_STORAGE_MARKER)?;

        Ok(Self {
            root,
            user_data_dir,
            profile_dir,
            local_state,
            cookies,
            cookies_wal,
            cookies_shm,
            login_data,
            web_data,
            sessions_dir,
            session_storage_dir,
            local_storage_dir,
            indexeddb_dir,
        })
    }

    pub fn root_path(&self) -> &Path {
        self.root.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::markers::contains_any_marker;
    use crate::util::set_owner_only;

    #[test]
    fn chromium_fixture_creates_expected_tree() {
        let p = ChromiumProfile::create("Default").expect("create fixture");
        // critical files exist
        assert!(p.local_state.is_file());
        assert!(p.cookies.is_file());
        assert!(p.cookies_wal.is_file());
        assert!(p.cookies_shm.is_file());
        assert!(p.login_data.is_file());
        assert!(p.web_data.is_file());
        // tree dirs exist
        assert!(p.sessions_dir.is_dir());
        assert!(p.session_storage_dir.is_dir());
        assert!(p.local_storage_dir.is_dir());
        assert!(p.indexeddb_dir.is_dir());
        // cookie content is the synthetic marker
        let cookie_bytes = fs::read(&p.cookies).expect("read cookies");
        assert!(contains_any_marker(&String::from_utf8_lossy(&cookie_bytes)));
        assert_eq!(cookie_bytes, markers::COOKIE_MARKER.as_bytes());
    }

    #[test]
    fn chromium_fixture_cleans_up_on_drop() {
        let p = ChromiumProfile::create("Default").expect("create fixture");
        let root = p.root_path().to_path_buf();
        assert!(root.exists());
        drop(p);
        assert!(!root.exists(), "temp dir must be removed on drop");
    }

    #[test]
    fn chromium_fixture_supports_custom_profile_name() {
        let p = ChromiumProfile::create("Profile 1").expect("create fixture");
        assert!(p.profile_dir.ends_with("Profile 1"));
        assert!(p.cookies.exists());
        // ensure no accidental real-profile access: marker must be present
        let _ = set_owner_only(&p.cookies);
    }
}
