//! Linux BPF LSM Process Shield boundary (LPS3).
//!
//! This is deliberately a small OS boundary: libbpf owns ELF loading and the
//! kernel link; portable policy never sees a BPF map fd. A target entry is an
//! exact PID plus `/proc` start-time instance, never a browser family or UID.

use std::collections::HashSet;
use std::ffi::{c_char, c_int, c_void, CString};
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread::JoinHandle;

use guard_core::resource::BrowserFamily;
use guard_core::TrustTier;
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
struct TargetInstance {
    start_jiffies: u64,
    hz: u32,
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
    fn bpf_program__attach_lsm(program: *const BpfProgram) -> *mut BpfLink;
    fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
    fn libbpf_get_error(pointer: *const c_void) -> i64;
}

const BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/guardd-process-shield.bpf.o"));

/// A loaded, attached, unpinned BPF LSM link. Dropping it removes protection
/// immediately; callers must therefore only claim ACTIVE while this is held.
pub struct ProcessShield {
    object: NonNull<BpfObject>,
    link: NonNull<BpfLink>,
    targets: NonNull<BpfMap>,
    clock_ticks: u32,
}

pub struct ProcessShieldRuntime {
    pub active: Arc<AtomicBool>,
    #[allow(dead_code)] // joins only at teardown; keeping it owns the BPF link.
    pub handle: JoinHandle<()>,
}

// libbpf object/link ownership moves once into the dedicated admission thread
// and is never shared; this opaque C handle therefore has the same Send
// contract as its owning thread.
unsafe impl Send for ProcessShield {}

impl ProcessShield {
    pub fn load() -> anyhow::Result<Self> {
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
        Ok(Self {
            object,
            link,
            targets,
            clock_ticks: ticks as u32,
        })
    }

    /// Admit one verified SecretAuthority instance. `start_jiffies` must have
    /// been read from the live instance after exact executable verification.
    pub fn admit(&self, pid: u32, start_jiffies: u64) -> anyhow::Result<()> {
        if pid == 0 || start_jiffies == 0 {
            anyhow::bail!("invalid Process Shield target identity");
        }
        let value = TargetInstance {
            start_jiffies,
            hz: self.clock_ticks,
        };
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
        Ok(())
    }
}

#[derive(Clone)]
struct FirefoxMainCandidate {
    uid: u32,
    exe: PathBuf,
}

/// Attach LPS3 and maintain its map from kernel-observed executable instances.
/// Only LPS2's accepted Firefox Main family is considered; unobserved children
/// and all other families cannot become targets through this path.
pub fn start_admission(
    browsers: &[BrowserEnrollmentConfig],
) -> anyhow::Result<ProcessShieldRuntime> {
    let candidates = browsers
        .iter()
        .filter(|browser| browser.family == BrowserFamily::Firefox)
        .filter_map(|browser| browser.owner_uid.map(|uid| (uid, &browser.exe_paths)))
        .flat_map(|(uid, paths)| paths.iter().map(move |path| (uid, path)))
        .filter_map(|(uid, path)| {
            std::fs::canonicalize(path)
                .ok()
                .map(|exe| FirefoxMainCandidate { uid, exe })
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        anyhow::bail!("Process Shield enabled but no explicit Firefox Main executable/owner candidate is configured");
    }
    let shield = ProcessShield::load()?;
    let active = Arc::new(AtomicBool::new(true));
    let loop_active = Arc::clone(&active);
    let handle = std::thread::Builder::new()
        .name("guardd-process-shield".into())
        .spawn(move || admission_loop(shield, candidates, loop_active))?;
    Ok(ProcessShieldRuntime { active, handle })
}

fn admission_loop(
    shield: ProcessShield,
    candidates: Vec<FirefoxMainCandidate>,
    active_state: Arc<AtomicBool>,
) {
    let mut enrolled = platform_linux::enrollment::EnrollmentStore::new();
    let mut active = HashSet::new();
    while !platform_linux::signal::is_shutdown() {
        let mut current = HashSet::new();
        let Ok(entries) = std::fs::read_dir("/proc") else {
            tracing::error!("Process Shield cannot enumerate /proc; retaining no new admissions");
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
                continue;
            };
            for candidate in &candidates {
                let Ok(identity) =
                    platform_linux::identity::resolve(pid, candidate.uid, &mut enrolled)
                else {
                    continue;
                };
                if identity.uid != candidate.uid
                    || identity.stable.exe != candidate.exe
                    || identity.trust_tier != TrustTier::SystemPackage
                    || !is_firefox_main(&identity.cmdline)
                {
                    continue;
                }
                if let Err(error) = shield.admit(identity.stable.pid, identity.stable.start_time) {
                    tracing::error!(pid = identity.stable.pid, err = %error, "Process Shield admission failed; refusing this target");
                    continue;
                }
                if !active.contains(&identity.stable.pid) {
                    tracing::info!(
                        pid = identity.stable.pid,
                        start_time = identity.stable.start_time,
                        exe = %identity.stable.exe.display(),
                        "Process Shield admitted exact Firefox Main instance"
                    );
                }
                current.insert(identity.stable.pid);
            }
        }
        for pid in active.difference(&current) {
            if let Err(error) = shield.remove(*pid) {
                tracing::warn!(pid, err = %error, "Process Shield stale target cleanup failed");
            }
        }
        active = current;
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    active_state.store(false, Ordering::Release);
}

fn is_firefox_main(argv: &[String]) -> bool {
    !argv.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "-contentproc" | "-utility" | "-gpu" | "-extension"
        )
    })
}

impl Drop for ProcessShield {
    fn drop(&mut self) {
        // SAFETY: both pointers are owned uniquely by this RAII wrapper.
        unsafe {
            bpf_link__destroy(self.link.as_ptr());
            bpf_object__close(self.object.as_ptr())
        };
    }
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
