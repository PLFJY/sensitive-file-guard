//! Synthetic Firefox browser profile generator.
//!
//! Builds a minimal Firefox profile tree containing harmless marker bytes in
//! place of real cookies, credentials, key material, Web Storage, and
//! explicitly unprotected profile state. Classifier tests use the complete
//! tree to verify both positive and negative scope boundaries.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use crate::markers;
use crate::util::write_file;

/// A synthetic Firefox profile rooted in a temp dir.
///
/// Dropping this value removes the entire temp tree.
pub struct FirefoxProfile {
    pub root: TempDir,
    pub profile_dir: PathBuf,
    pub cookies_sqlite: PathBuf,
    pub cookies_wal: PathBuf,
    pub logins_json: PathBuf,
    pub key4_db: PathBuf,
    pub webappsstore_sqlite: PathBuf,
    pub sessionstore_backups_dir: PathBuf,
    pub storage_dir: PathBuf,
}

impl FirefoxProfile {
    pub fn create(profile_name: &str) -> io::Result<Self> {
        let root = tempfile::tempdir()?;
        let profile_dir = root.path().join(profile_name);

        let cookies_sqlite = profile_dir.join("cookies.sqlite");
        let cookies_wal = profile_dir.join("cookies.sqlite-wal");
        let logins_json = profile_dir.join("logins.json");
        let key4_db = profile_dir.join("key4.db");
        let webappsstore_sqlite = profile_dir.join("webappsstore.sqlite");

        let sessionstore_backups_dir = profile_dir.join("sessionstore-backups");
        let storage_dir = profile_dir.join("storage");

        write_file(&cookies_sqlite, markers::FIREFOX_COOKIE_MARKER)?;
        write_file(&cookies_wal, markers::FIREFOX_COOKIE_MARKER)?;
        write_file(
            &logins_json,
            &format!(
                "{{\n  \"logins\": [\"{}\"]\n}}\n",
                markers::FIREFOX_LOGIN_MARKER
            ),
        )?;
        write_file(&key4_db, markers::FIREFOX_KEY_MARKER)?;
        write_file(&webappsstore_sqlite, markers::WEB_STORAGE_MARKER)?;

        fs::create_dir_all(&sessionstore_backups_dir)?;
        write_file(
            &sessionstore_backups_dir.join("recovery.jsonlz4"),
            markers::SESSION_MARKER,
        )?;

        let default_storage = storage_dir.join("default");
        fs::create_dir_all(&default_storage)?;
        write_file(
            &default_storage.join("https+++example.com.idb"),
            markers::WEB_STORAGE_MARKER,
        )?;

        Ok(Self {
            root,
            profile_dir,
            cookies_sqlite,
            cookies_wal,
            logins_json,
            key4_db,
            webappsstore_sqlite,
            sessionstore_backups_dir,
            storage_dir,
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

    #[test]
    fn firefox_fixture_creates_expected_tree() {
        let p = FirefoxProfile::create("test-profile").expect("create fixture");
        assert!(p.cookies_sqlite.is_file());
        assert!(p.cookies_wal.is_file());
        assert!(p.logins_json.is_file());
        assert!(p.key4_db.is_file());
        assert!(p.webappsstore_sqlite.is_file());
        assert!(p.sessionstore_backups_dir.is_dir());
        assert!(p.storage_dir.is_dir());

        let cookie_bytes = fs::read(&p.cookies_sqlite).expect("read cookies");
        assert!(contains_any_marker(&String::from_utf8_lossy(&cookie_bytes)));
        assert_eq!(cookie_bytes, markers::FIREFOX_COOKIE_MARKER.as_bytes());
    }

    #[test]
    fn firefox_fixture_cleans_up_on_drop() {
        let p = FirefoxProfile::create("test-profile").expect("create fixture");
        let root = p.root_path().to_path_buf();
        assert!(root.exists());
        drop(p);
        assert!(!root.exists(), "temp dir must be removed on drop");
    }
}
