//! Linux BPF LSM Process Shield boundary (LPS3).
//!
//! This is deliberately a small OS boundary: libbpf owns ELF loading and the
//! kernel link; portable policy never sees a BPF map fd. A target entry is an
//! exact PID plus `/proc` start-time instance, never a browser family or UID.

use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr::NonNull;

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
