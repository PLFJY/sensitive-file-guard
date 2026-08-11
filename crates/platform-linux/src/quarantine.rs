//! Conservative direct-executable quarantine.
//!
//! A candidate is eligible only when the incident's exact executable inode is
//! a regular, user-owned, user-writable non-system file. Before any pathname
//! mutation, the BPF LSM inode guard freezes competing rename/unlink/link and
//! ordinary write operations for that inode; the daemon is the sole exempt
//! mutator. This makes the subsequent identity recheck and move/delete a
//! compare-and-act transaction rather than a `stat(); rename()` race.

use std::fs::{self, File};
use std::io::{self, Read, Seek};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions as CapOpenOptions, OpenOptionsExt as CapOpenOptionsExt};
use guard_core::{ProcessIdentity, ProcessStableId, QuarantineCandidate, QuarantineCandidateKind};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::ssh_behavior::SshBehaviorBackend;

pub const QUARANTINE_ROOT: &str = "/var/lib/guardd/quarantine";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineResult {
    NoSafeCandidate,
    Quarantined { path: PathBuf, sha256: String },
}

/// Derive only two conservative candidate forms from kernel-observed process
/// identity: the executed user-writable file, or an absolute first script
/// argument to a trusted system interpreter.
pub fn candidate_for_process(process: &ProcessIdentity) -> Option<QuarantineCandidate> {
    let metadata = fs::symlink_metadata(&process.stable.exe).ok()?;
    if is_safe_direct_candidate(&process.stable.exe, &metadata, &process.stable, process.uid) {
        return Some(QuarantineCandidate {
            path: process.stable.exe.clone(),
            dev: process.stable.exe_dev,
            ino: process.stable.exe_ino,
            kind: QuarantineCandidateKind::DirectExecutable,
        });
    }
    if !matches!(process.trust_tier, guard_core::TrustTier::SystemPackage) {
        return None;
    }
    let script = PathBuf::from(process.cmdline.get(1)?);
    if !script.is_absolute() || is_system_path(&script) {
        return None;
    }
    let path = fs::canonicalize(script).ok()?;
    let metadata = fs::symlink_metadata(&path).ok()?;
    (metadata.file_type().is_file()
        && metadata.uid() == process.uid
        && metadata.mode() & 0o200 != 0)
        .then_some(QuarantineCandidate {
            path,
            dev: metadata.dev(),
            ino: metadata.ino(),
            kind: QuarantineCandidateKind::ExplicitScript,
        })
}

#[derive(Serialize)]
struct Metadata {
    incident_id: String,
    timestamp_ms: u64,
    original_path: String,
    original_dev: u64,
    original_ino: u64,
    owner_uid: u32,
    attribution_type: &'static str,
    sha256: String,
    reason: &'static str,
}

/// Quarantine the direct executable only when it is the exact incident inode
/// and meets the deliberately narrow candidate policy. Script arguments are
/// not guessed here; those need a separately pinned argv/cwd interpretation.
pub fn quarantine_direct_executable(
    root: &ProcessStableId,
    uid: u32,
    incident_id: &str,
    backend: &mut SshBehaviorBackend,
) -> Result<QuarantineResult, String> {
    let candidate = QuarantineCandidate {
        path: root.exe.clone(),
        dev: root.exe_dev,
        ino: root.exe_ino,
        kind: QuarantineCandidateKind::DirectExecutable,
    };
    quarantine_candidate(&candidate, uid, incident_id, backend)
}

pub fn quarantine_candidate(
    candidate: &QuarantineCandidate,
    uid: u32,
    incident_id: &str,
    backend: &mut SshBehaviorBackend,
) -> Result<QuarantineResult, String> {
    let metadata = match fs::symlink_metadata(&candidate.path) {
        Ok(metadata) => metadata,
        Err(_) => return Ok(QuarantineResult::NoSafeCandidate),
    };
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o200 == 0
        || metadata.dev() != candidate.dev
        || metadata.ino() != candidate.ino
        || is_system_path(&candidate.path)
    {
        return Ok(QuarantineResult::NoSafeCandidate);
    }
    let mut source = open_pinned_regular_file(&candidate.path, candidate.dev, candidate.ino)?;
    backend.arm_quarantine_inode(candidate.dev, candidate.ino)?;
    let result = quarantine_guarded(
        &mut source,
        &candidate.path,
        candidate.dev,
        candidate.ino,
        uid,
        incident_id,
        candidate.kind.clone(),
    );
    let clear = backend.disarm_quarantine_inode(candidate.dev, candidate.ino);
    match (result, clear) {
        (Ok(result), Ok(())) => Ok(result),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) | (Err(_), Err(error)) => {
            Err(format!("quarantine inode guard cleanup failed: {error}"))
        }
    }
}

fn is_safe_direct_candidate(
    path: &Path,
    metadata: &fs::Metadata,
    root: &ProcessStableId,
    uid: u32,
) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == uid
        && metadata.mode() & 0o200 != 0
        && metadata.dev() == root.exe_dev
        && metadata.ino() == root.exe_ino
        && !is_system_path(path)
}

fn is_system_path(path: &Path) -> bool {
    ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

fn open_pinned_regular_file(path: &Path, dev: u64, ino: u64) -> Result<File, String> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| "candidate path contains a NUL byte")?;
    let fd = unsafe {
        // SAFETY: path is NUL-terminated and flags are scalar open(2) flags.
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(format!(
            "open quarantine candidate: {}",
            io::Error::last_os_error()
        ));
    }
    let file = unsafe {
        // SAFETY: fd is newly returned and transferred to File ownership.
        File::from_raw_fd(fd)
    };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file() || metadata.dev() != dev || metadata.ino() != ino {
        return Err("quarantine candidate changed identity before inode guard armed".into());
    }
    Ok(file)
}

fn quarantine_guarded(
    source: &mut File,
    original: &Path,
    dev: u64,
    ino: u64,
    uid: u32,
    incident_id: &str,
    candidate_kind: QuarantineCandidateKind,
) -> Result<QuarantineResult, String> {
    let current = fs::symlink_metadata(original)
        .map_err(|error| format!("rechecking guarded candidate: {error}"))?;
    if !current.file_type().is_file() || current.dev() != dev || current.ino() != ino {
        return Err("quarantine candidate path changed before guarded move".into());
    }

    let (incident_dir, incident_path) =
        prepare_incident_dir(Path::new(QUARANTINE_ROOT), incident_id)?;
    let artifact = incident_path.join("artifact");
    let sha256 = sha256_file(source)?;
    if dev
        == fs::metadata(&incident_path)
            .map_err(|error| error.to_string())?
            .dev()
    {
        let parent = original
            .parent()
            .ok_or("quarantine candidate has no parent directory")?;
        let file_name = original
            .file_name()
            .ok_or("quarantine candidate has no file name")?;
        let source_dir = Dir::open_ambient_dir(parent, ambient_authority())
            .map_err(|error| format!("opening guarded source directory: {error}"))?;
        source_dir
            .rename(file_name, &incident_dir, "artifact")
            .map_err(|error| format!("moving guarded artifact with cap-std: {error}"))?;
    } else {
        copy_pinned_source(source, &incident_dir)?;
        let current = fs::symlink_metadata(original)
            .map_err(|error| format!("rechecking guarded source before unlink: {error}"))?;
        if !current.file_type().is_file() || current.dev() != dev || current.ino() != ino {
            return Err("quarantine candidate path changed before guarded unlink".into());
        }
        let parent = original
            .parent()
            .ok_or("quarantine candidate has no parent directory")?;
        let file_name = original
            .file_name()
            .ok_or("quarantine candidate has no file name")?;
        Dir::open_ambient_dir(parent, ambient_authority())
            .and_then(|dir| dir.remove_file(file_name))
            .map_err(|error| format!("removing guarded source with cap-std: {error}"))?;
    }
    fs::set_permissions(&artifact, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("restricting quarantined artifact: {error}"))?;
    write_metadata(
        &incident_dir,
        Metadata {
            incident_id: incident_id.into(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0),
            original_path: original.to_string_lossy().into_owned(),
            original_dev: dev,
            original_ino: ino,
            owner_uid: uid,
            attribution_type: match candidate_kind {
                QuarantineCandidateKind::DirectExecutable => "direct_executable",
                QuarantineCandidateKind::ExplicitScript => "explicit_script",
            },
            sha256: sha256.clone(),
            reason: "sensitive_key_network_activity",
        },
    )?;
    Ok(QuarantineResult::Quarantined {
        path: artifact,
        sha256,
    })
}

fn prepare_incident_dir(root: &Path, incident_id: &str) -> Result<(Dir, PathBuf), String> {
    if incident_id.len() != 20
        || !incident_id.starts_with("ssh-")
        || !incident_id[4..]
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("invalid incident id for quarantine path".into());
    }
    Dir::create_ambient_dir_all(root, ambient_authority())
        .map_err(|error| format!("creating quarantine root with cap-std: {error}"))?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("securing quarantine root: {error}"))?;
    let root_dir = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|error| format!("opening quarantine root with cap-std: {error}"))?;
    let incident_dir = root.join(incident_id);
    root_dir
        .create_dir(incident_id)
        .map_err(|error| format!("creating quarantine incident directory with cap-std: {error}"))?;
    fs::set_permissions(&incident_dir, fs::Permissions::from_mode(0o700))
        .map_err(|error| format!("securing quarantine incident directory: {error}"))?;
    let directory = root_dir
        .open_dir(incident_id)
        .map_err(|error| format!("opening quarantine incident directory: {error}"))?;
    Ok((directory, incident_dir))
}

fn sha256_file(source: &mut File) -> Result<String, String> {
    let mut hash = Sha256::new();
    source
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error| format!("rewinding quarantine source: {error}"))?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| format!("hashing quarantine source: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn copy_pinned_source(source: &mut File, incident_dir: &Dir) -> Result<(), String> {
    source
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error| format!("rewinding quarantine source: {error}"))?;
    let mut options = CapOpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut destination = incident_dir
        .open_with("artifact", &options)
        .map_err(|error| format!("creating quarantined copy with cap-std: {error}"))?;
    io::copy(source, &mut destination)
        .map_err(|error| format!("copying quarantined artifact: {error}"))?;
    destination
        .sync_all()
        .map_err(|error| format!("fsync quarantined artifact: {error}"))
}

fn write_metadata(incident_dir: &Dir, metadata: Metadata) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(&metadata).map_err(|error| error.to_string())?;
    let mut options = CapOpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let mut file = incident_dir
        .open_with("metadata.json", &options)
        .map_err(|error| format!("creating quarantine metadata with cap-std: {error}"))?;
    use std::io::Write;
    file.write_all(&bytes)
        .map_err(|error| format!("writing quarantine metadata: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("fsync quarantine metadata: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn direct_candidate_requires_the_exact_user_writable_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("probe");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)
            .unwrap();
        file.write_all(b"synthetic").unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let root = ProcessStableId {
            pid: 1,
            start_time: 1,
            exe: path.clone(),
            exe_dev: metadata.dev(),
            exe_ino: metadata.ino(),
        };
        assert!(is_safe_direct_candidate(&path, &metadata, &root, unsafe {
            libc::getuid()
        }));
        assert!(!is_safe_direct_candidate(
            Path::new("/usr/bin/node"),
            &metadata,
            &root,
            unsafe { libc::getuid() }
        ));
    }

    #[test]
    fn incident_directory_is_private_and_rejects_path_tricks() {
        let dir = tempfile::tempdir().unwrap();
        let (_, created) = prepare_incident_dir(dir.path(), "ssh-0000000000000001").unwrap();
        assert_eq!(
            fs::metadata(&created).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(prepare_incident_dir(dir.path(), "../not-an-id").is_err());
    }

    #[test]
    fn trusted_interpreter_accepts_only_an_absolute_first_script_argument() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("probe.js");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&script)
            .unwrap();
        let interpreter = PathBuf::from("/bin/sh");
        let metadata = fs::metadata(&interpreter).unwrap();
        let process = ProcessIdentity {
            stable: ProcessStableId {
                pid: 1,
                start_time: 1,
                exe: interpreter.clone(),
                exe_dev: metadata.dev(),
                exe_ino: metadata.ino(),
            },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            exe_owner_uid: 0,
            browser: None,
            trust_tier: guard_core::TrustTier::SystemPackage,
            cmdline: vec![
                interpreter.to_string_lossy().into_owned(),
                script.to_string_lossy().into_owned(),
            ],
            ancestors: Vec::new(),
        };
        assert!(matches!(
            candidate_for_process(&process),
            Some(QuarantineCandidate {
                kind: QuarantineCandidateKind::ExplicitScript,
                ..
            })
        ));
    }
}
