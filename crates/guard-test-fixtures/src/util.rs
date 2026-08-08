//! Small filesystem helpers shared by fixture generators.

use std::fs;
use std::io;
use std::path::Path;

/// Writes `contents` to `path`, creating parent directories as needed.
pub fn write_file(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}

/// Writes `bytes` to `path`, creating parent directories as needed.
pub fn write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)
}

/// Sets restrictive (0600) permissions on a file, on Unix.
#[cfg(unix)]
pub fn set_owner_only(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
pub fn set_owner_only(_path: &Path) -> io::Result<()> {
    Ok(())
}
