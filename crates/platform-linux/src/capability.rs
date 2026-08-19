//! Linux capability detection and runtime inventory (LFH0).
//!
//! Two layers:
//! 1. Static/effective-capability checks (`CAP_SYS_ADMIN`) used to fail fast.
//! 2. Runtime feature probes that produce a truthful capability inventory
//!    (fanotify permission events, `FAN_MARK_FILESYSTEM`, `FAN_REPORT_PIDFD`,
//!    `name_to_handle_at(AT_EMPTY_PATH)`, BPF LSM availability). The inventory
//!    never infers support from a distro name; every claim is a probe result.

use std::fs;
use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;

use serde::Serialize;

/// Capability number for `CAP_SYS_ADMIN` (Linux UAPI).
pub const CAP_SYS_ADMIN: u32 = 21;

/// Parse the `CapEff:` line from `/proc/self/status` text into a bitmask.
///
/// Pure function for unit testing.
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:\t") {
            return u64::from_str_radix(rest.trim(), 16).ok();
        }
    }
    None
}

/// Read this process's effective capability set.
pub fn effective_caps() -> io::Result<u64> {
    let status = fs::read_to_string("/proc/self/status")?;
    parse_cap_eff(&status).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "CapEff missing"))
}

/// Returns true if the current process has `CAP_SYS_ADMIN` in its effective set.
pub fn has_cap_sys_admin() -> bool {
    effective_caps()
        .map(|c| c & (1u64 << CAP_SYS_ADMIN) != 0)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Runtime capability inventory
// ---------------------------------------------------------------------------

/// One probe verdict. `supported` is only true when the probe syscall actually
/// succeeded; everything else carries the exact errno/message.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProbeResult {
    pub name: String,
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ProbeResult {
    fn ok(name: &str, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            supported: true,
            detail: Some(detail.into()),
        }
    }

    fn fail(name: &str, err: &io::Error) -> Self {
        Self {
            name: name.to_owned(),
            supported: false,
            detail: Some(format!("{}: {}", err.raw_os_error().unwrap_or(-1), err)),
        }
    }
}

/// `name_to_handle_at(AT_EMPTY_PATH)` support on one filesystem. A filesystem
/// without file-handle support (or a kernel without the syscall) cannot give
/// the object-handle identity LFH2 needs; that must degrade truthfully.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FsHandleProbe {
    pub path: String,
    pub supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Full inventory snapshot. Serialized as JSON by `guardctl capabilities`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapabilityReport {
    pub kernel: String,
    pub cap_sys_admin: bool,
    pub fanotify_permission_events: ProbeResult,
    pub fanotify_mark_filesystem: ProbeResult,
    pub fanotify_report_pidfd: ProbeResult,
    pub name_to_handle_at_syscall: ProbeResult,
    pub filesystem_handles: Vec<FsHandleProbe>,
    pub bpf_lsm: BpfLsmProbe,
}

/// BPF LSM availability (inventory only; Process Shield is a separate goal).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BpfLsmProbe {
    pub btf_vmlinux_present: bool,
    pub bpf_lsm_config: BpfLsmConfig,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum BpfLsmConfig {
    /// `CONFIG_BPF_LSM=y` found in a readable kernel config.
    Enabled,
    /// Kernel config not readable from this process (common on Arch without
    /// `/proc/config.gz`); availability is unknown, not claimed.
    Unreadable(String),
    /// `CONFIG_BPF_LSM` present but not `=y`.
    NotEnabled,
}

fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

/// Probe fanotify permission-event support by initializing a
/// `FAN_CLASS_CONTENT` group. Requires `CAP_SYS_ADMIN`; without it the probe
/// reports the EPERM truthfully rather than claiming unsupported.
pub fn probe_fanotify_permission() -> ProbeResult {
    // SAFETY: fanotify_init is a pure kernel fd allocation; flags are UAPI.
    let fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC,
            (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(libc::EPERM) {
            ProbeResult {
                name: "fanotify_permission_events".to_owned(),
                supported: false,
                detail: Some(
                    "EPERM: FAN_CLASS_CONTENT requires CAP_SYS_ADMIN (probe ran without it)"
                        .to_owned(),
                ),
            }
        } else {
            ProbeResult::fail("fanotify_permission_events", &err)
        };
    }
    // SAFETY: fd is an owned fanotify fd just created by the kernel.
    unsafe {
        libc::close(fd);
    }
    ProbeResult::ok(
        "fanotify_permission_events",
        "FAN_CLASS_CONTENT group initialized",
    )
}

/// Probe `FAN_MARK_FILESYSTEM` by marking a temporary directory's filesystem.
/// This only verifies the mark syscall; it never blocks any real open.
pub fn probe_fanotify_mark_filesystem(tmp: &Path) -> ProbeResult {
    // SAFETY: see probe_fanotify_permission.
    let fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC,
            (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint,
        )
    };
    if fd < 0 {
        return ProbeResult::fail("fanotify_mark_filesystem", &io::Error::last_os_error());
    }
    let c = std::ffi::CString::new(tmp.to_string_lossy().as_bytes())
        .unwrap_or_else(|_| std::ffi::CString::new("/").unwrap());
    // SAFETY: fd valid, c NUL-terminated and outlives the call.
    let rc = unsafe {
        libc::fanotify_mark(
            fd,
            libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
            libc::FAN_OPEN_PERM,
            libc::AT_FDCWD,
            c.as_ptr(),
        )
    };
    // SAFETY: fd is owned by this probe and closed exactly once.
    unsafe {
        libc::close(fd);
    }
    if rc < 0 {
        return ProbeResult::fail("fanotify_mark_filesystem", &io::Error::last_os_error());
    }
    ProbeResult::ok(
        "fanotify_mark_filesystem",
        "FAN_MARK_FILESYSTEM mark accepted on temp filesystem",
    )
}

/// Probe `FAN_REPORT_PIDFD` by requesting it at group creation. The flag only
/// matters when the permission group is created with it; a legacy kernel
/// rejects it with EINVAL.
pub fn probe_fanotify_pidfd() -> ProbeResult {
    // SAFETY: same as probe_fanotify_permission; FAN_REPORT_PIDFD is UAPI.
    let fd = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | 0x0000_0080, // FAN_REPORT_PIDFD
            (libc::O_RDONLY | libc::O_LARGEFILE) as libc::c_uint,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        let detail = match err.raw_os_error() {
            Some(libc::EINVAL) => {
                "EINVAL: kernel does not support FAN_REPORT_PIDFD with FAN_CLASS_CONTENT"
            }
            Some(libc::EPERM) => "EPERM: FAN_CLASS_CONTENT requires CAP_SYS_ADMIN",
            _ => "unsupported",
        };
        return ProbeResult {
            name: "fanotify_report_pidfd".to_owned(),
            supported: false,
            detail: Some(detail.to_owned()),
        };
    }
    // SAFETY: fd is an owned fanotify fd just created by the kernel.
    unsafe {
        libc::close(fd);
    }
    ProbeResult::ok(
        "fanotify_report_pidfd",
        "FAN_REPORT_PIDFD accepted at group creation",
    )
}

/// Probe the `name_to_handle_at(AT_EMPTY_PATH)` syscall on one open fd.
///
/// The kernel's documented two-call pattern returns `EOVERFLOW` on the first
/// call when the supplied buffer is too small (it then reports the required
/// `handle_bytes`). EOVERFLOW therefore proves the filesystem/kernel supports
/// handles; we retry with the reported size to confirm a full success.
fn probe_name_to_handle_syscall(fd: RawFd) -> ProbeResult {
    // SAFETY: zeroed struct file_handle is valid for a two-call sequence;
    // name_to_handle_at fills it and reports the required size on EOVERFLOW.
    let mut handle: libc::file_handle = unsafe { std::mem::zeroed() };
    let mut mount_id: libc::c_int = 0;
    // SAFETY: handle is writable, mount_id is writable, AT_EMPTY_PATH with an
    // empty name is the documented way to resolve an open fd by its own inode.
    let rc = unsafe {
        libc::name_to_handle_at(
            fd,
            c"".as_ptr(),
            &mut handle,
            &mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    };
    if rc >= 0 {
        return ProbeResult::ok(
            "name_to_handle_at(AT_EMPTY_PATH)",
            format!(
                "handle_type={} handle_bytes={} mount_id={}",
                handle.handle_type, handle.handle_bytes, mount_id
            ),
        );
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EOVERFLOW) {
        // First call: buffer too small, kernel reports required size. Retry
        // with an adequate buffer to prove a complete success.
        let needed = handle.handle_bytes;
        if needed == 0 || needed > 4096 {
            return ProbeResult::fail(
                "name_to_handle_at(AT_EMPTY_PATH)",
                &io::Error::from_raw_os_error(libc::EOVERFLOW),
            );
        }
        let mut sized: Vec<u8> =
            vec![0; std::mem::size_of::<libc::file_handle>() + needed as usize];
        let handle_ptr = sized.as_mut_ptr() as *mut libc::file_handle;
        // SAFETY: sized buffer covers the file_handle header + payload; the
        // kernel writes at most `needed` payload bytes.
        let mut handle2: libc::file_handle = unsafe { std::ptr::read(handle_ptr) };
        handle2.handle_bytes = needed;
        // SAFETY: write the header back with the correct size, then retry.
        unsafe {
            std::ptr::write(handle_ptr, handle2);
        }
        let rc2 = unsafe {
            libc::name_to_handle_at(
                fd,
                c"".as_ptr(),
                handle_ptr,
                &mut mount_id,
                libc::AT_EMPTY_PATH,
            )
        };
        if rc2 < 0 {
            return ProbeResult::fail(
                "name_to_handle_at(AT_EMPTY_PATH)",
                &io::Error::last_os_error(),
            );
        }
        // SAFETY: kernel returned success, so the header fields are valid.
        let filled: libc::file_handle = unsafe { std::ptr::read(handle_ptr) };
        return ProbeResult::ok(
            "name_to_handle_at(AT_EMPTY_PATH)",
            format!(
                "handle_type={} handle_bytes={} mount_id={}",
                filled.handle_type, filled.handle_bytes, mount_id
            ),
        );
    }
    ProbeResult::fail("name_to_handle_at(AT_EMPTY_PATH)", &err)
}

/// Probe `name_to_handle_at(AT_EMPTY_PATH)` on a path from each protected
/// filesystem. Returns one entry per distinct device observed.
pub fn probe_filesystem_handles(paths: &[&Path]) -> Vec<FsHandleProbe> {
    let mut seen_devices: Vec<u64> = Vec::new();
    let mut out = Vec::new();
    for path in paths {
        let Ok(meta) = fs::metadata(path) else {
            continue;
        };
        use std::os::unix::fs::MetadataExt;
        let dev = meta.dev();
        if seen_devices.contains(&dev) {
            continue;
        }
        seen_devices.push(dev);
        let fs_path = if meta.is_dir() {
            path.to_path_buf()
        } else {
            path.parent().unwrap_or(path).to_path_buf()
        };
        // Open with O_PATH|O_CLOEXEC: no read permission needed, no data read.
        let c = std::ffi::CString::new(fs_path.to_string_lossy().as_bytes())
            .unwrap_or_else(|_| std::ffi::CString::new("/").unwrap());
        // SAFETY: open with O_PATH|O_CLOEXEC on a valid path; fd is owned below.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            out.push(FsHandleProbe {
                path: fs_path.display().to_string(),
                supported: false,
                detail: Some(format!("open(O_PATH): {}", io::Error::last_os_error())),
            });
            continue;
        }
        let result = probe_name_to_handle_syscall(fd);
        // SAFETY: fd is owned by this probe and closed exactly once.
        unsafe {
            libc::close(fd);
        }
        out.push(FsHandleProbe {
            path: fs_path.display().to_string(),
            supported: result.supported,
            detail: result.detail,
        });
    }
    out
}

/// BPF LSM availability inventory. `CONFIG_BPF_LSM=y` is read from the kernel
/// config when one is readable; otherwise the verdict is explicitly
/// `Unreadable` — never a claimed "unsupported".
pub fn probe_bpf_lsm() -> BpfLsmProbe {
    let btf = Path::new("/sys/kernel/btf/vmlinux").exists();
    BpfLsmProbe {
        btf_vmlinux_present: btf,
        bpf_lsm_config: bpf_lsm_config(),
    }
}

fn bpf_lsm_config() -> BpfLsmConfig {
    // Try the most common readable locations in order.
    let candidates: Vec<std::path::PathBuf> = vec![
        Path::new("/proc/config.gz").to_path_buf(),
        Path::new("/boot").join(format!("config-{}", kernel_release())),
        Path::new("/lib/modules")
            .join(kernel_release())
            .join("config"),
    ];
    let Some(candidate) = candidates.into_iter().find(|p| p.exists()) else {
        return BpfLsmConfig::Unreadable(
            "no readable kernel config found (/proc/config.gz not enabled)".into(),
        );
    };
    let bytes = match fs::read(&candidate) {
        Ok(b) => b,
        Err(e) => return BpfLsmConfig::Unreadable(format!("{}: {e}", candidate.display())),
    };
    if candidate.extension().and_then(|e| e.to_str()) == Some("gz") {
        if let Some(text) = gunzip_to_string(&bytes) {
            return classify_bpf_lsm_config(&text, &candidate);
        }
        return BpfLsmConfig::Unreadable(format!("{}: failed to decompress", candidate.display()));
    }
    if let Ok(text) = String::from_utf8(bytes) {
        return classify_bpf_lsm_config(&text, &candidate);
    }
    BpfLsmConfig::Unreadable(format!("{}: not UTF-8 text", candidate.display()))
}

/// Minimal gzip decompression via the `gzip` binary when present. Avoids adding
/// a compression dependency for an inventory-only probe.
fn gunzip_to_string(bytes: &[u8]) -> Option<String> {
    let mut child = std::process::Command::new("gzip")
        .arg("-dc")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    use std::io::Write;
    child.stdin.take()?.write_all(bytes).ok()?;
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

fn classify_bpf_lsm_config(text: &str, source: &Path) -> BpfLsmConfig {
    if text
        .lines()
        .any(|line| line.trim_start() == "CONFIG_BPF_LSM=y")
    {
        return BpfLsmConfig::Enabled;
    }
    if text.lines().any(|line| line.contains("CONFIG_BPF_LSM")) {
        return BpfLsmConfig::NotEnabled;
    }
    BpfLsmConfig::Unreadable(format!(
        "{}: CONFIG_BPF_LSM absent from config",
        source.display()
    ))
}

/// Build the full inventory. `protected_paths` are paths on the filesystems to
/// probe for object-handle support (browser profile roots + SSH key parents).
pub fn inventory(protected_paths: &[&Path], tmp: &Path) -> CapabilityReport {
    let fanotify_permission = probe_fanotify_permission();
    let fanotify_mark_filesystem = if fanotify_permission.supported {
        probe_fanotify_mark_filesystem(tmp)
    } else {
        // Without permission events the mark probe would also EPERM; report the
        // root cause once instead of a confusing second EPERM.
        ProbeResult {
            name: "fanotify_mark_filesystem".to_owned(),
            supported: false,
            detail: Some("skipped: fanotify permission group unavailable".to_owned()),
        }
    };
    CapabilityReport {
        kernel: kernel_release(),
        cap_sys_admin: has_cap_sys_admin(),
        fanotify_permission_events: fanotify_permission,
        fanotify_mark_filesystem,
        fanotify_report_pidfd: probe_fanotify_pidfd(),
        name_to_handle_at_syscall: probe_name_to_handle_syscall_on_self(),
        filesystem_handles: probe_filesystem_handles(protected_paths),
        bpf_lsm: probe_bpf_lsm(),
    }
}

/// Probe the syscall on a harmless self fd (`/proc/self/exe` cannot be opened
/// O_PATH portably on all kernels; use our own binary path via /proc/self/exe
/// readlink fallback, then a tempfile).
fn probe_name_to_handle_syscall_on_self() -> ProbeResult {
    let self_exe = match fs::read_link("/proc/self/exe") {
        Ok(p) => p,
        Err(e) => {
            return ProbeResult::fail(
                "name_to_handle_at(AT_EMPTY_PATH)",
                &io::Error::new(e.kind(), format!("readlink /proc/self/exe: {e}")),
            )
        }
    };
    let c = std::ffi::CString::new(self_exe.to_string_lossy().as_bytes())
        .unwrap_or_else(|_| std::ffi::CString::new("/").unwrap());
    // SAFETY: open O_PATH|O_CLOEXEC of our own running image; fd owned below.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return ProbeResult::fail(
            "name_to_handle_at(AT_EMPTY_PATH)",
            &io::Error::last_os_error(),
        );
    }
    let result = probe_name_to_handle_syscall(fd);
    // SAFETY: fd owned by this probe, closed exactly once.
    unsafe {
        libc::close(fd);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cap_eff_line() {
        let sample = "Name:\tguardd\nUmask:\t0022\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t0000000000400000\nCapBnd:\t000001ffffffffff\n";
        // 0x400000 == 1 << 22 (cap_sys_ptrace), not sys_admin (21)
        let caps = parse_cap_eff(sample).expect("present");
        assert_eq!(caps, 0x400000);
        assert!(!has_sys_admin(caps));
    }

    #[test]
    fn detects_sys_admin_bit() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert!(has_sys_admin(caps));
    }

    #[test]
    fn missing_line_is_none() {
        assert!(parse_cap_eff("Name:\tfoo\n").is_none());
    }

    fn has_sys_admin(caps: u64) -> bool {
        caps & (1u64 << CAP_SYS_ADMIN) != 0
    }

    #[test]
    fn bpf_lsm_config_classification() {
        let text = "CONFIG_BPF=y\nCONFIG_BPF_LSM=y\nCONFIG_BPF_UNPRIV_DEFAULT_OFF=y\n";
        assert_eq!(
            classify_bpf_lsm_config(text, Path::new("/fake")),
            BpfLsmConfig::Enabled
        );
        let text2 = "CONFIG_BPF_LSM=m\n";
        assert_eq!(
            classify_bpf_lsm_config(text2, Path::new("/fake")),
            BpfLsmConfig::NotEnabled
        );
        let text3 = "CONFIG_BPF=y\n";
        assert!(matches!(
            classify_bpf_lsm_config(text3, Path::new("/fake")),
            BpfLsmConfig::Unreadable(_)
        ));
    }
}
