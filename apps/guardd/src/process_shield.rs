//! Linux BPF LSM Process Shield boundary (LPS3).
//!
//! This is deliberately a small OS boundary: libbpf owns ELF loading and the
//! kernel link; portable policy never sees a BPF map fd. A target entry is an
//! exact PID plus `/proc` start-time instance, never a browser family or UID.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void, CString};
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;

use guard_audit::AuditStore;
use guard_core::resource::{
    BrowserFamily, ProtectedResource, ProtectedResourceId, ProtectedResourceKind,
};
use guard_core::TrustTier;
use guard_core::{Decision, DenyReason};
use platform_linux::config::BrowserEnrollmentConfig;

#[repr(C)]
struct BpfObject(c_void);
#[repr(C)]
struct BpfProgram(c_void);
#[repr(C)]
struct BpfMap(c_void);
#[repr(C)]
struct BpfLink(c_void);
#[repr(C)]
struct RingBuffer(c_void);

#[repr(C)]
struct TargetInstance {
    start_jiffies: u64,
    hz: u32,
}

#[repr(C)]
struct BpfAuditEvent {
    requester_pid: u32,
    target_pid: u32,
    target_start_jiffies: u64,
    operation_kind: u32,
}

#[derive(Clone, Copy)]
struct TargetMetadata {
    uid: u32,
    start_jiffies: u64,
}

struct AuditContext {
    audit: Arc<AuditStore>,
    targets: Arc<std::sync::Mutex<HashMap<u32, TargetMetadata>>>,
}

#[link(name = "bpf")]
unsafe extern "C" {
    fn bpf_object__open_mem(
        bytes: *const c_void,
        length: usize,
        options: *const c_void,
    ) -> *mut BpfObject;
    fn bpf_object__load(object: *mut BpfObject) -> c_int;
    fn bpf_object__close(object: *mut BpfObject);
    fn bpf_object__find_map_by_name(object: *const BpfObject, name: *const c_char) -> *mut BpfMap;
    fn bpf_object__find_program_by_name(
        object: *const BpfObject,
        name: *const c_char,
    ) -> *mut BpfProgram;
    fn bpf_map__update_elem(
        map: *const BpfMap,
        key: *const c_void,
        key_size: usize,
        value: *const c_void,
        value_size: usize,
        flags: u64,
    ) -> c_int;
    fn bpf_map__delete_elem(
        map: *const BpfMap,
        key: *const c_void,
        key_size: usize,
        flags: u64,
    ) -> c_int;
    fn bpf_map__fd(map: *const BpfMap) -> c_int;
    fn bpf_map__key_size(map: *const BpfMap) -> u32;
    fn bpf_map__value_size(map: *const BpfMap) -> u32;
    fn bpf_program__attach_lsm(program: *const BpfProgram) -> *mut BpfLink;
    fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
    fn ring_buffer__new(
        map_fd: c_int,
        callback: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> c_int,
        context: *mut c_void,
        options: *const c_void,
    ) -> *mut RingBuffer;
    fn ring_buffer__poll(buffer: *mut RingBuffer, timeout_ms: c_int) -> c_int;
    fn ring_buffer__free(buffer: *mut RingBuffer);
    fn libbpf_get_error(pointer: *const c_void) -> i64;
}

const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/guardd-process-shield.bpf.o"));

/// A loaded, attached, unpinned BPF LSM link. Dropping it removes protection
/// immediately; callers must therefore only claim ACTIVE while this is held.
pub struct ProcessShield {
    object: NonNull<BpfObject>,
    link: NonNull<BpfLink>,
    targets: NonNull<BpfMap>,
    ring: NonNull<RingBuffer>,
    audit_context: Box<AuditContext>,
    clock_ticks: u32,
}

pub struct ProcessShieldRuntime {
    pub active: Arc<AtomicBool>,
    pub admission: ProcessShieldAdmission,
    #[allow(dead_code)] // joins only at teardown; keeping it owns the BPF link.
    pub handle: JoinHandle<()>,
}

/// Synchronous, pre-response admission path. It is intentionally separate
/// from browser identity: only a File Shield WebStorage allow can call it.
#[derive(Clone)]
pub struct ProcessShieldAdmission {
    shield: Arc<std::sync::Mutex<ProcessShield>>,
    candidates: Arc<Vec<FirefoxMainCandidate>>,
}

// libbpf object/link ownership moves once into the dedicated admission thread
// and is never shared; this opaque C handle therefore has the same Send
// contract as its owning thread.
unsafe impl Send for ProcessShield {}

impl ProcessShield {
    pub fn load(audit: Arc<AuditStore>) -> anyhow::Result<Self> {
        // SAFETY: BPF_OBJECT has static lifetime and is a clang-produced ELF.
        let object = unsafe {
            bpf_object__open_mem(
                BPF_OBJECT.as_ptr().cast(),
                BPF_OBJECT.len(),
                std::ptr::null(),
            )
        };
        let object = NonNull::new(object)
            .ok_or_else(|| anyhow::anyhow!("libbpf could not open Process Shield object"))?;
        // SAFETY: object came from bpf_object__open_mem and is still owned here.
        if unsafe { bpf_object__load(object.as_ptr()) } != 0 {
            // SAFETY: object was successfully opened and must be closed once.
            unsafe { bpf_object__close(object.as_ptr()) };
            anyhow::bail!(
                "libbpf could not load Process Shield BPF LSM object: {}",
                std::io::Error::last_os_error()
            );
        }
        let targets = find_map(object, "targets")?;
        let audit_map = find_map(object, "audit")?;
        let program = find_program(object, "guardd_process_shield_ptrace")?;
        // SAFETY: program belongs to loaded object. libbpf returns an ERR_PTR
        // on failure, which libbpf_get_error recognizes before NonNull use.
        let raw_link = unsafe { bpf_program__attach_lsm(program.as_ptr()) };
        if raw_link.is_null() || unsafe { libbpf_get_error(raw_link.cast()) } != 0 {
            // SAFETY: object is still owned on every attach-failure path.
            unsafe { bpf_object__close(object.as_ptr()) };
            anyhow::bail!(
                "libbpf could not attach Process Shield LSM hook: {}",
                std::io::Error::last_os_error()
            );
        }
        let link = NonNull::new(raw_link).expect("checked non-null link");
        let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if ticks <= 0 || ticks > u32::MAX as libc::c_long {
            // SAFETY: release the just-attached link and its object.
            unsafe {
                bpf_link__destroy(link.as_ptr());
                bpf_object__close(object.as_ptr())
            };
            anyhow::bail!("invalid host clock tick rate for Process Shield");
        }
        let mut audit_context = Box::new(AuditContext {
            audit,
            targets: Arc::new(std::sync::Mutex::new(HashMap::new())),
        });
        // SAFETY: context is owned by ProcessShield until ring_buffer__free;
        // callback uses only the fixed BPF event layout below.
        let raw_ring = unsafe {
            ring_buffer__new(
                bpf_map__fd(audit_map.as_ptr()),
                on_audit,
                (&mut *audit_context as *mut AuditContext).cast(),
                std::ptr::null(),
            )
        };
        if raw_ring.is_null() || unsafe { libbpf_get_error(raw_ring.cast()) } != 0 {
            unsafe {
                bpf_link__destroy(link.as_ptr());
                bpf_object__close(object.as_ptr())
            };
            anyhow::bail!(
                "libbpf could not create Process Shield audit ring: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(Self {
            object,
            link,
            targets,
            ring: NonNull::new(raw_ring).expect("checked non-null ring"),
            audit_context,
            clock_ticks: ticks as u32,
        })
    }

    /// Admit one verified SecretAuthority instance. `start_jiffies` must have
    /// been read from the live instance after exact executable verification.
    pub fn admit(&self, pid: u32, start_jiffies: u64, uid: u32) -> anyhow::Result<()> {
        if pid == 0 || start_jiffies == 0 {
            anyhow::bail!("invalid Process Shield target identity");
        }
        let value = TargetInstance {
            start_jiffies,
            hz: self.clock_ticks,
        };
        // Reject a loader/object ABI mismatch before touching a target. This
        // protects against silently treating an environmental ptrace denial
        // as a Process Shield decision when the map was never populated.
        let key_size = unsafe { bpf_map__key_size(self.targets.as_ptr()) } as usize;
        let value_size = unsafe { bpf_map__value_size(self.targets.as_ptr()) } as usize;
        if key_size != std::mem::size_of::<u32>()
            || value_size != std::mem::size_of::<TargetInstance>()
        {
            anyhow::bail!(
                "Process Shield target map ABI mismatch: kernel map key/value sizes {key_size}/{value_size}, userspace {}/{}",
                std::mem::size_of::<u32>(),
                std::mem::size_of::<TargetInstance>(),
            );
        }
        // SAFETY: map/key/value layouts exactly match process_shield.bpf.c;
        // libbpf validates sizes against the loaded map before the syscall.
        let rc = unsafe {
            bpf_map__update_elem(
                self.targets.as_ptr(),
                (&pid as *const u32).cast(),
                std::mem::size_of_val(&pid),
                (&value as *const TargetInstance).cast(),
                std::mem::size_of_val(&value),
                0,
            )
        };
        if rc != 0 {
            anyhow::bail!(
                "updating Process Shield target map: {}",
                std::io::Error::last_os_error()
            );
        }
        self.audit_context
            .targets
            .lock()
            .expect("Process Shield target mutex poisoned")
            .insert(pid, TargetMetadata { uid, start_jiffies });
        Ok(())
    }

    fn remove(&self, pid: u32) -> anyhow::Result<()> {
        let rc = unsafe {
            bpf_map__delete_elem(
                self.targets.as_ptr(),
                (&pid as *const u32).cast(),
                std::mem::size_of::<u32>(),
                0,
            )
        };
        if rc != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            anyhow::bail!(
                "removing stale Process Shield target: {}",
                std::io::Error::last_os_error()
            );
        }
        self.audit_context
            .targets
            .lock()
            .expect("Process Shield target mutex poisoned")
            .remove(&pid);
        Ok(())
    }

    fn poll_audit(&self) {
        // SAFETY: ring is owned until Drop and callback context remains valid.
        let rc = unsafe { ring_buffer__poll(self.ring.as_ptr(), 0) };
        if rc < 0 {
            tracing::warn!(errno = -rc, "Process Shield audit ring poll failed");
        }
    }

    fn stale_targets(&self) -> Vec<u32> {
        self.audit_context
            .targets
            .lock()
            .expect("Process Shield target mutex poisoned")
            .iter()
            .filter_map(|(&pid, target)| {
                (platform_linux::identity::read_start_time(pid as i32).ok()
                    != Some(target.start_jiffies))
                .then_some(pid)
            })
            .collect()
    }
}

#[derive(Clone)]
struct FirefoxMainCandidate {
    uid: u32,
    exe: PathBuf,
    profile_root: PathBuf,
}

/// Attach LPS3 and maintain its map from kernel-observed executable instances.
/// Only LPS2's accepted Firefox Main family is considered; unobserved children
/// and all other families cannot become targets through this path.
pub fn start_admission(
    browsers: &[BrowserEnrollmentConfig],
    audit: Arc<AuditStore>,
) -> anyhow::Result<ProcessShieldRuntime> {
    let candidates = browsers
        .iter()
        .filter(|browser| browser.family == BrowserFamily::Firefox)
        .filter_map(|browser| {
            let uid = browser.owner_uid?;
            let profile_root = std::fs::canonicalize(&browser.profile_root).ok()?;
            Some((uid, profile_root, &browser.exe_paths))
        })
        .flat_map(|(uid, profile_root, paths)| {
            paths
                .iter()
                .map(move |path| (uid, profile_root.clone(), path))
        })
        .filter_map(|(uid, profile_root, path)| {
            std::fs::canonicalize(path)
                .ok()
                .map(|exe| FirefoxMainCandidate {
                    uid,
                    exe,
                    profile_root,
                })
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        anyhow::bail!("Process Shield enabled but no explicit Firefox Main executable/owner candidate is configured");
    }
    let shield = Arc::new(std::sync::Mutex::new(ProcessShield::load(audit)?));
    let admission = ProcessShieldAdmission {
        shield: Arc::clone(&shield),
        candidates: Arc::new(candidates),
    };
    let active = Arc::new(AtomicBool::new(true));
    let loop_active = Arc::clone(&active);
    let handle = std::thread::Builder::new()
        .name("guardd-process-shield".into())
        .spawn({
            let shield = Arc::clone(&shield);
            move || cleanup_loop(shield, loop_active)
        })?;
    Ok(ProcessShieldRuntime {
        active,
        admission,
        handle,
    })
}

impl ProcessShieldAdmission {
    /// Admit only a live Firefox Main that exactly matches an LPS2-proven
    /// configured profile. The caller invokes this before it grants the
    /// protected WebStorage open, so polling can never be the security edge.
    pub fn admit_from_file_shield(&self, pid: i32) -> anyhow::Result<bool> {
        let mut enrolled = platform_linux::enrollment::EnrollmentStore::new();
        for candidate in self.candidates.iter() {
            let Ok(identity) = platform_linux::identity::resolve(pid, candidate.uid, &mut enrolled)
            else {
                continue;
            };
            if identity.uid != candidate.uid
                || identity.stable.exe != candidate.exe
                || identity.trust_tier != TrustTier::SystemPackage
                || !is_exact_firefox_main(&identity.cmdline, &candidate.profile_root)
            {
                continue;
            }
            self.shield
                .lock()
                .expect("Process Shield mutex poisoned")
                .admit(
                    identity.stable.pid,
                    identity.stable.start_time,
                    identity.uid,
                )?;
            tracing::info!(
                pid = identity.stable.pid,
                start_time = identity.stable.start_time,
                exe = %identity.stable.exe.display(),
                "Process Shield admitted exact Firefox Main from File Shield WebStorage allow"
            );
            return Ok(true);
        }
        Ok(false)
    }
}

fn cleanup_loop(shield: Arc<std::sync::Mutex<ProcessShield>>, active_state: Arc<AtomicBool>) {
    while !platform_linux::signal::is_shutdown() {
        let shield = shield.lock().expect("Process Shield mutex poisoned");
        shield.poll_audit();
        let stale = shield.stale_targets();
        for pid in stale {
            if let Err(error) = shield.remove(pid) {
                tracing::warn!(pid, err = %error, "Process Shield stale target cleanup failed");
            }
        }
        drop(shield);
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    active_state.store(false, Ordering::Release);
}

fn is_exact_firefox_main(argv: &[String], profile_root: &std::path::Path) -> bool {
    let is_child = argv.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "-contentproc" | "-utility" | "-gpu" | "-extension"
        )
    });
    if is_child {
        return false;
    }
    // A bare executable or `-P` profile name cannot be bound to a configured
    // filesystem authority. Do not admit it merely because it is Firefox.
    argv.windows(2).any(|pair| {
        matches!(pair[0].as_str(), "--profile" | "-profile")
            && std::fs::canonicalize(&pair[1])
                .map(|path| path == profile_root)
                .unwrap_or(false)
    })
}

impl Drop for ProcessShield {
    fn drop(&mut self) {
        // SAFETY: both pointers are owned uniquely by this RAII wrapper.
        unsafe {
            ring_buffer__free(self.ring.as_ptr());
            bpf_link__destroy(self.link.as_ptr());
            bpf_object__close(self.object.as_ptr())
        };
    }
}

unsafe extern "C" fn on_audit(context: *mut c_void, data: *mut c_void, size: usize) -> c_int {
    if context.is_null() || data.is_null() || size != std::mem::size_of::<BpfAuditEvent>() {
        return 0;
    }
    // SAFETY: libbpf invokes this synchronously with the fixed-size BPF event.
    let context = unsafe { &*(context as *const AuditContext) };
    let event = unsafe { &*(data as *const BpfAuditEvent) };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Some(target) = context
            .targets
            .lock()
            .expect("Process Shield target mutex poisoned")
            .get(&event.target_pid)
            .copied()
        else {
            return;
        };
        if target.start_jiffies != event.target_start_jiffies {
            return;
        }
        let process = platform_linux::identity::resolve(
            event.requester_pid as i32,
            target.uid,
            &mut platform_linux::enrollment::EnrollmentStore::new(),
        )
        .ok();
        let resource = ProtectedResource {
            id: ProtectedResourceId("process-shield-ptrace".into()),
            kind: ProtectedResourceKind::Other,
            owner_uid: target.uid,
            browser: None,
            profile: None,
            path: PathBuf::from(format!("/proc/{}/ptrace", event.target_pid)),
        };
        let mut record = crate::enforce::build_audit_record(
            &resource,
            process.as_ref(),
            Decision::Deny(DenyReason::UnknownProcess),
            &format!(
                "process_shield_ptrace;target_pid={};target_start={};operation_kind={}",
                event.target_pid, event.target_start_jiffies, event.operation_kind
            ),
        );
        record.event_code = "process_shield_ptrace_denied".into();
        context.audit.record(record);
    }));
    if result.is_err() {
        tracing::error!("Process Shield audit callback panicked");
    }
    0
}

fn find_map(object: NonNull<BpfObject>, name: &str) -> anyhow::Result<NonNull<BpfMap>> {
    let name = CString::new(name)?;
    // SAFETY: object is valid and name is NUL-terminated for this call.
    NonNull::new(unsafe { bpf_object__find_map_by_name(object.as_ptr(), name.as_ptr()) })
        .ok_or_else(|| anyhow::anyhow!("Process Shield BPF map {name:?} is missing"))
}

fn find_program(object: NonNull<BpfObject>, name: &str) -> anyhow::Result<NonNull<BpfProgram>> {
    let name = CString::new(name)?;
    // SAFETY: object is valid and name is NUL-terminated for this call.
    NonNull::new(unsafe { bpf_object__find_program_by_name(object.as_ptr(), name.as_ptr()) })
        .ok_or_else(|| anyhow::anyhow!("Process Shield BPF program {name:?} is missing"))
}

#[cfg(test)]
mod tests {
    use super::is_exact_firefox_main;

    #[test]
    fn admission_requires_exact_configured_profile() {
        let profile = std::env::temp_dir().join(format!("sfg-lps3-profile-{}", std::process::id()));
        std::fs::create_dir_all(&profile).unwrap();
        let canonical = std::fs::canonicalize(&profile).unwrap();
        assert!(is_exact_firefox_main(
            &[
                "/usr/lib/firefox/firefox".into(),
                "--profile".into(),
                profile.display().to_string()
            ],
            &canonical,
        ));
        assert!(!is_exact_firefox_main(
            &[
                "/usr/lib/firefox/firefox".into(),
                "--profile".into(),
                "/tmp/another-profile".into()
            ],
            &canonical,
        ));
        assert!(!is_exact_firefox_main(
            &[
                "/usr/lib/firefox/firefox".into(),
                "-P".into(),
                "default".into()
            ],
            &canonical,
        ));
        assert!(!is_exact_firefox_main(
            &[
                "/usr/lib/firefox/firefox".into(),
                "--profile".into(),
                profile.display().to_string(),
                "-contentproc".into()
            ],
            &canonical,
        ));
        std::fs::remove_dir_all(profile).unwrap();
    }
}
