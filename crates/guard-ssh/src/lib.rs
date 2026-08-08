//! SSH private-key protection: candidate detection, suggestion, and enrollment.
//!
//! Phase 10. Provides the path/identity-based detection used by `guardctl ssh
//! protect PATH` and `guardctl ssh suggest`, plus the `ProtectedResource`
//! constructor used by the daemon (both at config load and at runtime via IPC).
//!
//! Security rules (see `10_SSH_PRIVATE_KEY_PROTECTION.md`):
//! - public keys (`.pub`) are NEVER treated as private keys
//! - reserved names (`known_hosts`, `authorized_keys*`, `config`) are NEVER
//!   treated as private keys
//! - we do NOT parse, hash, or log key contents; protection is anchored on
//!   path + inode/dev file identity
//! - `suggest` only lists conventional `~/.ssh/id_*` files excluding `.pub`
//!
//! This crate never touches the developer's real `~/.ssh`; callers pass an
//! explicit directory.

use std::path::{Path, PathBuf};

use guard_core::resource::{ProtectedResource, ProtectedResourceId, ProtectedResourceKind};

/// File names that must NEVER be treated as SSH private keys, even if they live
/// under `~/.ssh`. Public keys, host-known lists, and the ssh config are
/// explicitly excluded by the detection policy.
const RESERVED_NON_PRIVATE_NAMES: &[&str] = &[
    "known_hosts",
    "known_hosts2",
    "authorized_keys",
    "authorized_keys2",
    "config",
];

/// Returns true if `path` is a plausible SSH private-key file.
///
/// A file is a candidate iff:
/// - its file name does NOT end in `.pub`
/// - its file name is not a reserved non-private name (`known_hosts`,
///   `authorized_keys*`, `config`)
///
/// Detection is purely name-based: we deliberately do NOT read file contents
/// (the spec prefers path/inode identity and forbids hashing/logging key
/// bytes). An explicit `guardctl ssh protect PATH` enrollment reuses this check
/// to refuse obviously-non-private names; any other file the user explicitly
/// names is accepted.
pub fn is_private_key_candidate(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    if name.ends_with(".pub") {
        return false;
    }
    if RESERVED_NON_PRIVATE_NAMES.contains(&name) {
        return false;
    }
    true
}

/// Suggest conventional private-key files under `ssh_dir` (typically `~/.ssh`),
/// excluding `.pub` and reserved names. Returns canonical paths that exist and
/// are regular files, sorted lexicographically. Never reads or returns file
/// contents.
///
/// "Conventional" means the file name starts with `id_` (e.g. `id_ed25519`,
/// `id_rsa`, `id_ecdsa`). This is a safe auto-suggestion list; the user still
/// enrolls explicitly via `guardctl ssh protect PATH`.
pub fn suggest_keys(ssh_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let read = match std::fs::read_dir(ssh_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e),
    };
    for entry in read {
        let entry = entry?;
        let ft = entry.file_type()?;
        if !ft.is_file() && !ft.is_symlink() {
            continue;
        }
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.starts_with("id_") {
            continue;
        }
        if !is_private_key_candidate(&path) {
            continue;
        }
        // Canonicalize so the suggested path is what `protect` would enroll.
        // A broken symlink is silently skipped.
        match std::fs::canonicalize(&path) {
            Ok(c) => {
                if c.is_file() {
                    out.push(c);
                }
            }
            Err(_) => continue,
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Build a `ProtectedResource` (kind = `SshPrivateKey`) for `path`. The path is
/// canonicalized and `owner_uid` is taken from the file's actual stat owner
/// (the file owner is authoritative for SSH keys).
///
/// Returns an error if the path does not exist, is not a regular file, or is
/// not a private-key candidate (e.g. a `.pub` file). No file contents are read.
pub fn enroll_key(path: &Path) -> std::io::Result<ProtectedResource> {
    if !is_private_key_candidate(path) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is not a private-key candidate (public key or reserved name)",
                path.display()
            ),
        ));
    }
    let canon = std::fs::canonicalize(path)?;
    let md = std::fs::metadata(&canon)?;
    if !md.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", canon.display()),
        ));
    }
    use std::os::unix::fs::MetadataExt;
    let owner_uid = md.uid();
    Ok(ProtectedResource {
        id: ProtectedResourceId(canon.to_string_lossy().into_owned()),
        kind: ProtectedResourceKind::SshPrivateKey,
        owner_uid,
        browser: None,
        profile: None,
        path: canon,
    })
}

#[cfg(test)]
mod tests {
    //! Detection / suggestion / enrollment tests. All use an isolated temp
    //! `.ssh`-like tree; no test touches the developer's real `~/.ssh`.

    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn touch(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, b"x").unwrap();
        p
    }

    #[test]
    fn candidate_rejects_pub_and_reserved_names() {
        assert!(!is_private_key_candidate(Path::new("id_ed25519.pub")));
        assert!(!is_private_key_candidate(Path::new("id_rsa.pub")));
        assert!(!is_private_key_candidate(Path::new("known_hosts")));
        assert!(!is_private_key_candidate(Path::new("known_hosts2")));
        assert!(!is_private_key_candidate(Path::new("authorized_keys")));
        assert!(!is_private_key_candidate(Path::new("authorized_keys2")));
        assert!(!is_private_key_candidate(Path::new("config")));
    }

    #[test]
    fn candidate_accepts_conventional_and_custom_private_keys() {
        assert!(is_private_key_candidate(Path::new("id_ed25519")));
        assert!(is_private_key_candidate(Path::new("id_rsa")));
        assert!(is_private_key_candidate(Path::new("id_ecdsa")));
        assert!(is_private_key_candidate(Path::new("my_deploy_key")));
        assert!(is_private_key_candidate(Path::new("github_key")));
    }

    #[test]
    fn suggest_lists_only_id_files_excluding_pub() {
        let dir = TempDir::new().unwrap();
        touch(dir.path(), "id_ed25519");
        touch(dir.path(), "id_ed25519.pub");
        touch(dir.path(), "id_rsa");
        touch(dir.path(), "id_rsa.pub");
        touch(dir.path(), "known_hosts");
        touch(dir.path(), "config");
        touch(dir.path(), "authorized_keys");
        touch(dir.path(), "deploy_key"); // non-conventional, not suggested

        let mut suggested = suggest_keys(dir.path()).unwrap();
        suggested.sort();
        let names: Vec<String> = suggested
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["id_ed25519".to_string(), "id_rsa".to_string()]);
    }

    #[test]
    fn suggest_on_missing_dir_returns_empty() {
        let suggested = suggest_keys(Path::new("/nonexistent/does/not/exist")).unwrap();
        assert!(suggested.is_empty());
    }

    #[test]
    fn enroll_key_builds_ssh_resource() {
        let dir = TempDir::new().unwrap();
        let key = touch(dir.path(), "id_ed25519");
        let res = enroll_key(&key).unwrap();
        assert_eq!(res.kind, ProtectedResourceKind::SshPrivateKey);
        assert!(res.browser.is_none());
        assert!(res.profile.is_none());
        assert!(res.path.is_absolute());
        assert_eq!(res.path, std::fs::canonicalize(&key).unwrap());
    }

    #[test]
    fn enroll_key_rejects_pub_file() {
        let dir = TempDir::new().unwrap();
        let pub_key = touch(dir.path(), "id_ed25519.pub");
        let err = enroll_key(&pub_key).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn enroll_key_rejects_reserved_name() {
        let dir = TempDir::new().unwrap();
        let kh = touch(dir.path(), "known_hosts");
        let err = enroll_key(&kh).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn enroll_key_rejects_missing_file() {
        let err = enroll_key(Path::new("/nonexistent/key")).unwrap_err();
        assert!(matches!(
            err.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::Other
        ));
    }

    #[test]
    fn enroll_key_rejects_directory() {
        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("id_ed25519");
        fs::create_dir(&sub).unwrap();
        let err = enroll_key(&sub).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn enroll_key_owner_uid_from_file_stat() {
        let dir = TempDir::new().unwrap();
        let key = touch(dir.path(), "id_ed25519");
        let res = enroll_key(&key).unwrap();
        // The file is owned by the test process's uid.
        use std::os::unix::fs::MetadataExt;
        let expected = std::fs::metadata(&key).unwrap().uid();
        assert_eq!(res.owner_uid, expected);
    }
}
