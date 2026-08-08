//! Synthetic SSH directory fixture.
//!
//! Creates a fake `~/.ssh`-like tree containing a **non-real** private-key-like
//! file with a harmless marker. This is deliberately NOT a parseable OpenSSH
//! private key: it exists only to exercise path/identity-based protection and
//! to assert that key bytes never leak into logs. Phase 10/Phase 11 tests that
//! need a real loadable key generate an ephemeral keypair via `ssh-keygen`
//! under an isolated `HOME`; this fixture is for protection/detection tests.
//!
//! This fixture never touches the developer's real `~/.ssh`.

use std::io;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use crate::markers;
use crate::util::{set_owner_only, write_file};

/// A synthetic `.ssh` directory rooted in an isolated temp HOME.
///
/// Dropping this value removes the entire temp tree.
pub struct SshFixture {
    pub home: TempDir,
    pub ssh_dir: PathBuf,
    /// A non-real private-key-like file (marker content only).
    pub private_key: PathBuf,
    pub public_key: PathBuf,
    pub config: PathBuf,
    pub known_hosts: PathBuf,
}

impl SshFixture {
    pub fn create() -> io::Result<Self> {
        let home = tempfile::tempdir()?;
        let ssh_dir = home.path().join(".ssh");
        std::fs::create_dir_all(&ssh_dir)?;

        let private_key = ssh_dir.join("id_ed25519_fake");
        let public_key = ssh_dir.join("id_ed25519_fake.pub");
        let config = ssh_dir.join("config");
        let known_hosts = ssh_dir.join("known_hosts");

        // NOT a real private key. Harmless marker content only.
        let private_content = format!(
            "-----BEGIN GUARD SYNTHETIC PRIVATE KEY-----\n{}\n\
             -----END GUARD SYNTHETIC PRIVATE KEY-----\n",
            markers::SSH_PRIVATE_KEY_MARKER
        );
        write_file(&private_key, &private_content)?;
        set_owner_only(&private_key)?;

        write_file(
            &public_key,
            &format!("{} fake@example\n", markers::SSH_PUBLIC_KEY_MARKER),
        )?;
        write_file(&config, "# synthetic ssh config\n")?;
        write_file(&known_hosts, "# synthetic known_hosts\n")?;

        Ok(Self {
            home,
            ssh_dir,
            private_key,
            public_key,
            config,
            known_hosts,
        })
    }

    pub fn home_path(&self) -> &Path {
        self.home.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::markers::contains_any_marker;

    #[test]
    fn ssh_fixture_creates_expected_tree() {
        let s = SshFixture::create().expect("create fixture");
        assert!(s.private_key.is_file());
        assert!(s.public_key.is_file());
        assert!(s.config.is_file());
        assert!(s.known_hosts.is_file());

        let priv_bytes = std::fs::read(&s.private_key).expect("read private key");
        let priv_str = String::from_utf8_lossy(&priv_bytes);
        assert!(contains_any_marker(&priv_str));
        assert!(priv_str.contains(markers::SSH_PRIVATE_KEY_MARKER));
        // public key must remain readable (not protected)
        let pub_bytes = std::fs::read(&s.public_key).expect("read public key");
        assert!(String::from_utf8_lossy(&pub_bytes).contains(markers::SSH_PUBLIC_KEY_MARKER));
    }

    #[test]
    fn ssh_fixture_cleans_up_on_drop() {
        let s = SshFixture::create().expect("create fixture");
        let home = s.home_path().to_path_buf();
        assert!(home.exists());
        drop(s);
        assert!(!home.exists(), "temp home must be removed on drop");
    }

    #[cfg(unix)]
    #[test]
    fn ssh_private_key_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let s = SshFixture::create().expect("create fixture");
        let mode = std::fs::metadata(&s.private_key)
            .expect("stat private key")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "private key must be 0600");
    }
}
