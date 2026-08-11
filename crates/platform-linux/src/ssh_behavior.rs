//! Linux BPF-LSM backend for bounded SSH read-to-send containment.
//!
//! The BPF object blocks the first actual send, inherits armed state only to
//! future process children, removes a process leader's state on exit, and
//! carries the existing quarantine LSM guards. No network payload, TLS
//! plaintext, hostname, or key bytes are inspected.

use std::ffi::{c_char, c_int, c_long, c_void, CString};
use std::fs;
use std::io;
use std::mem::size_of;
use std::ptr;

use guard_core::SshIncidentState;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshBehaviorBackendStatus {
    Active,
    Unavailable { reason: String },
    Degraded { reason: String },
}

impl SshBehaviorBackendStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Unavailable { .. } => "UNAVAILABLE",
            Self::Degraded { .. } => "DEGRADED",
        }
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Active => None,
            Self::Unavailable { reason } | Self::Degraded { reason } => Some(reason),
        }
    }
}

/// A blocked send reported by the kernel. Destination fields are deliberately
/// absent: this first backend does not dereference socket internals merely to
/// decorate an alert. It still blocks the send before socket transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockedSend {
    pub incident_id: u64,
    pub at_ns: u64,
    pub tgid: u32,
    pub uid: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ExposureValue {
    incident_id: u64,
    observe_until_ns: u64,
    state: u32,
    uid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InodeKey {
    dev: u64,
    ino: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawBlockedSend {
    incident_id: u64,
    at_ns: u64,
    tgid: u32,
    uid: u32,
    size: u32,
    _reserved: u32,
}

/// Heap-pinned separately from the movable backend owner because libbpf keeps
/// this address as its callback context for the ring buffer lifetime.
struct EventQueue(Vec<BlockedSend>);

const EXPOSURE_OBSERVING: u32 = 1;
const EXPOSURE_PENDING: u32 = 2;
const EXPOSURE_ALLOWED: u32 = 3;
const BPF_ANY: u64 = 0;
const EMBEDDED_BPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/ssh_behavior.bpf.o"));

enum BpfObject {}
enum BpfProgram {}
enum BpfMap {}
enum BpfLink {}
enum RingBuffer {}

/// ABI-compatible layout of libbpf's bpf_object_open_opts for the supported
/// libbpf API. The kernel log buffer lets a privileged deployment distinguish
/// capability denial from verifier failure.
#[repr(C)]
struct BpfObjectOpenOpts {
    sz: usize,
    object_name: *const c_char,
    relaxed_maps: bool,
    _relaxed_maps_padding: [u8; 7],
    pin_root_path: *const c_char,
    _removed_attach_prog_fd: u32,
    _removed_attach_prog_fd_padding: u32,
    kconfig: *const c_char,
    btf_custom_path: *const c_char,
    kernel_log_buf: *mut c_char,
    kernel_log_size: usize,
    kernel_log_level: u32,
    _kernel_log_level_padding: u32,
    bpf_token_path: *const c_char,
}

#[link(name = "bpf")]
unsafe extern "C" {
    fn bpf_object__open_mem(
        object: *const c_void,
        object_size: usize,
        options: *const c_void,
    ) -> *mut BpfObject;
    fn libbpf_get_error(pointer: *const c_void) -> c_long;
    fn bpf_object__load(object: *mut BpfObject) -> c_int;
    fn bpf_object__close(object: *mut BpfObject);
    fn bpf_object__find_program_by_name(
        object: *const BpfObject,
        name: *const c_char,
    ) -> *mut BpfProgram;
    fn bpf_object__find_map_by_name(object: *const BpfObject, name: *const c_char) -> *mut BpfMap;
    fn bpf_map__fd(map: *const BpfMap) -> c_int;
    fn bpf_program__attach_lsm(program: *const BpfProgram) -> *mut BpfLink;
    fn bpf_program__attach_tracepoint(
        program: *const BpfProgram,
        category: *const c_char,
        name: *const c_char,
    ) -> *mut BpfLink;
    fn bpf_program__attach_trace(program: *const BpfProgram) -> *mut BpfLink;
    fn bpf_link__destroy(link: *mut BpfLink) -> c_int;
    fn bpf_map_update_elem(
        fd: c_int,
        key: *const c_void,
        value: *const c_void,
        flags: u64,
    ) -> c_int;
    fn bpf_map_lookup_elem(fd: c_int, key: *const c_void, value: *mut c_void) -> c_int;
    fn bpf_map_get_next_key(fd: c_int, key: *const c_void, next_key: *mut c_void) -> c_int;
    fn bpf_map_delete_elem(fd: c_int, key: *const c_void) -> c_int;
    fn ring_buffer__new(
        map_fd: c_int,
        callback: unsafe extern "C" fn(*mut c_void, *mut c_void, usize) -> c_int,
        context: *mut c_void,
        options: *const c_void,
    ) -> *mut RingBuffer;
    fn ring_buffer__poll(buffer: *mut RingBuffer, timeout_ms: c_int) -> c_int;
    fn ring_buffer__epoll_fd(buffer: *const RingBuffer) -> c_int;
    fn ring_buffer__free(buffer: *mut RingBuffer);
}

/// Owns the loaded BPF object, its three links, and the ring-buffer reader.
/// All mutation is performed by the privileged daemon under its engine lock.
pub struct SshBehaviorBackend {
    object: *mut BpfObject,
    send_link: *mut BpfLink,
    fork_link: *mut BpfLink,
    exit_link: *mut BpfLink,
    quarantine_links: Vec<*mut BpfLink>,
    exposures_fd: c_int,
    pending_tgids_fd: c_int,
    quarantine_inodes_fd: c_int,
    ring: *mut RingBuffer,
    events: Box<EventQueue>,
}

/// Semantic adapter around the Linux network-containment backend. The BPF map,
/// hook, and ring-buffer handles remain private to this module.
#[derive(Clone, Debug)]
pub struct LinuxSshExposure {
    incident_id: u64,
    tgid: u32,
    uid: u32,
}

pub struct LinuxSshBehavior {
    backend: std::sync::Mutex<SshBehaviorBackend>,
}

impl LinuxSshBehavior {
    pub fn new(backend: SshBehaviorBackend) -> Self {
        Self {
            backend: std::sync::Mutex::new(backend),
        }
    }
}

impl guard_platform::SshBehavior for LinuxSshBehavior {
    type Exposure = LinuxSshExposure;

    fn arm_exposure(
        &self,
        incident_id: &str,
        process: &guard_core::ProcessIdentity,
        until_ms: u64,
    ) -> anyhow::Result<Self::Exposure> {
        let incident_id = incident_id
            .strip_prefix("ssh-")
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .ok_or_else(|| anyhow::anyhow!("invalid SSH incident identifier"))?;
        let tgid = crate::identity::read_tgid(i32::try_from(process.stable.pid)?)?;
        let exposure = LinuxSshExposure {
            incident_id,
            tgid,
            uid: process.uid,
        };
        self.backend
            .lock()
            .map_err(|_| anyhow::anyhow!("SSH backend mutex poisoned"))?
            .arm(
                tgid,
                incident_id,
                process.uid,
                until_ms.saturating_mul(1_000_000),
                guard_core::SshIncidentState::Observing,
            )
            .map_err(anyhow::Error::msg)?;
        Ok(exposure)
    }

    fn renew_exposure(&self, exposure: &Self::Exposure, until_ms: u64) -> anyhow::Result<()> {
        self.backend
            .lock()
            .map_err(|_| anyhow::anyhow!("SSH backend mutex poisoned"))?
            .arm(
                exposure.tgid,
                exposure.incident_id,
                exposure.uid,
                until_ms.saturating_mul(1_000_000),
                guard_core::SshIncidentState::Observing,
            )
            .map_err(anyhow::Error::msg)
    }

    fn poll_blocked_attempts(&self) -> anyhow::Result<Vec<guard_platform::BlockedNetworkAttempt>> {
        let events = self
            .backend
            .lock()
            .map_err(|_| anyhow::anyhow!("SSH backend mutex poisoned"))?
            .poll()
            .map_err(anyhow::Error::msg)?;
        Ok(events
            .into_iter()
            .map(|event| guard_platform::BlockedNetworkAttempt {
                incident_id: format!("ssh-{:016x}", event.incident_id),
                pid: event.tgid,
                uid: event.uid,
                destination: None,
            })
            .collect())
    }

    fn allow_incident(&self, incident_id: &str) -> anyhow::Result<()> {
        self.resolve_incident(incident_id, true)
    }

    fn block_incident(&self, incident_id: &str) -> anyhow::Result<()> {
        self.resolve_incident(incident_id, false)
    }

    fn remove_exposure(&self, exposure: Self::Exposure) -> anyhow::Result<()> {
        self.backend
            .lock()
            .map_err(|_| anyhow::anyhow!("SSH backend mutex poisoned"))?
            .resolve(exposure.incident_id, true)
            .map_err(anyhow::Error::msg)
    }
}

impl LinuxSshBehavior {
    fn resolve_incident(&self, incident_id: &str, allow: bool) -> anyhow::Result<()> {
        let incident_id = incident_id
            .strip_prefix("ssh-")
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .ok_or_else(|| anyhow::anyhow!("invalid SSH incident identifier"))?;
        self.backend
            .lock()
            .map_err(|_| anyhow::anyhow!("SSH backend mutex poisoned"))?
            .resolve(incident_id, allow)
            .map_err(anyhow::Error::msg)
    }
}

// libbpf objects are used only by the daemon's synchronized backend owner.
// Links and map fds are process-owned kernel handles, and Drop tears them down
// exactly once after polling stops.
unsafe impl Send for SshBehaviorBackend {}

impl SshBehaviorBackend {
    /// Load the embedded BPF ELF and attach every required program. A caller
    /// SSH reads remain allowed if this fails; only network containment is
    /// unavailable in that case.
    pub fn attach() -> Result<Self, String> {
        let mut verifier_log = vec![0u8; 64 * 1024];
        let options = BpfObjectOpenOpts {
            sz: size_of::<BpfObjectOpenOpts>(),
            object_name: ptr::null(),
            relaxed_maps: false,
            _relaxed_maps_padding: [0; 7],
            pin_root_path: ptr::null(),
            _removed_attach_prog_fd: 0,
            _removed_attach_prog_fd_padding: 0,
            kconfig: ptr::null(),
            btf_custom_path: ptr::null(),
            kernel_log_buf: verifier_log.as_mut_ptr().cast(),
            kernel_log_size: verifier_log.len(),
            // Let libbpf request verifier output only on a failed load; a
            // successful startup must not pay for verbose verifier logging.
            kernel_log_level: 0,
            _kernel_log_level_padding: 0,
            bpf_token_path: ptr::null(),
        };
        let object = unsafe {
            // SAFETY: EMBEDDED_BPF is immutable Cargo-built ELF data. The
            // options object and verifier buffer remain alive through open/load.
            bpf_object__open_mem(
                EMBEDDED_BPF.as_ptr().cast(),
                EMBEDDED_BPF.len(),
                (&options as *const BpfObjectOpenOpts).cast(),
            )
        };
        if let Some(error) = pointer_error(object) {
            return Err(error.context("opening embedded BPF object"));
        }
        if unsafe { bpf_object__load(object) } != 0 {
            let load_errno = io::Error::last_os_error();
            unsafe {
                // SAFETY: object is a successfully opened libbpf object.
                bpf_object__close(object);
            }
            return Err(load_error(&verifier_log, load_errno));
        }

        let result = Self::attach_loaded(object);
        if result.is_err() {
            unsafe {
                // SAFETY: links created before an attach failure are owned by
                // the partially constructed result and explicitly cleaned by
                // attach_loaded before it returns an error.
                bpf_object__close(object);
            }
        }
        result
    }

    fn attach_loaded(object: *mut BpfObject) -> Result<Self, String> {
        let send = find_program(object, "guard_socket_sendmsg")?;
        let fork = find_program(object, "guard_future_child")?;
        let exit = find_program(object, "guard_process_exit")?;
        let exposures = find_map_fd(object, "exposures")?;
        let event_map = find_map_fd(object, "blocked_events")?;
        let pending_tgids = find_map_fd(object, "pending_tgids")?;
        let quarantine_inodes = find_map_fd(object, "quarantine_inodes")?;
        let quarantine_controller = find_map_fd(object, "quarantine_controller")?;

        let send_link = unsafe {
            // SAFETY: send is a program loaded from this object with an LSM
            // section and libbpf owns its backing object.
            bpf_program__attach_lsm(send)
        };
        if let Some(error) = pointer_error(send_link) {
            return Err(error.context("attaching BPF LSM socket_sendmsg hook"));
        }
        let fork_link = unsafe {
            // SAFETY: fork is a loaded BTF-aware tracepoint program and
            // libbpf owns the returned link.
            bpf_program__attach_trace(fork)
        };
        if let Some(error) = pointer_error(fork_link) {
            destroy_link(send_link);
            return Err(error.context("attaching sched_process_fork hook"));
        }
        let category = CString::new("sched").expect("literal has no NUL");
        let exit_name = CString::new("sched_process_exit").expect("literal has no NUL");
        let exit_link = unsafe {
            // SAFETY: literals remain alive through the attach call and exit
            // is a loaded tracepoint program.
            bpf_program__attach_tracepoint(exit, category.as_ptr(), exit_name.as_ptr())
        };
        if let Some(error) = pointer_error(exit_link) {
            destroy_link(fork_link);
            destroy_link(send_link);
            return Err(error.context("attaching sched_process_exit hook"));
        }

        let mut quarantine_links = Vec::new();
        for name in [
            "guard_quarantine_link",
            "guard_quarantine_unlink",
            "guard_quarantine_rename",
            "guard_quarantine_setattr",
            "guard_quarantine_file_permission",
        ] {
            let program = match find_program(object, name) {
                Ok(program) => program,
                Err(error) => {
                    destroy_links(&quarantine_links);
                    destroy_link(exit_link);
                    destroy_link(fork_link);
                    destroy_link(send_link);
                    return Err(error);
                }
            };
            let link = unsafe {
                // SAFETY: each named program is loaded from this object with
                // an LSM section and libbpf owns its backing object.
                bpf_program__attach_lsm(program)
            };
            if let Some(error) = pointer_error(link) {
                destroy_links(&quarantine_links);
                destroy_link(exit_link);
                destroy_link(fork_link);
                destroy_link(send_link);
                return Err(error.context("attaching BPF LSM quarantine hook"));
            }
            quarantine_links.push(link);
        }

        let zero = 0u32;
        let controller = std::process::id();
        let controller_result = unsafe {
            // SAFETY: the array map's key/value match initialized u32 values;
            // the exact daemon TGID is the only BPF quarantine-map mutator.
            bpf_map_update_elem(
                quarantine_controller,
                (&zero as *const u32).cast(),
                (&controller as *const u32).cast(),
                BPF_ANY,
            )
        };
        if controller_result != 0 {
            destroy_links(&quarantine_links);
            destroy_link(exit_link);
            destroy_link(fork_link);
            destroy_link(send_link);
            return Err(last_error("setting BPF quarantine controller"));
        }

        let mut events = Box::new(EventQueue(Vec::new()));
        let ring = unsafe {
            // SAFETY: events is heap-pinned for the lifetime of the ring;
            // callback copies a fixed-size kernel event before returning.
            ring_buffer__new(
                event_map,
                receive_event,
                (&mut *events as *mut EventQueue).cast(),
                ptr::null(),
            )
        };
        if let Some(error) = pointer_error(ring) {
            destroy_links(&quarantine_links);
            destroy_link(exit_link);
            destroy_link(fork_link);
            destroy_link(send_link);
            return Err(error.context("creating BPF blocked-send ring buffer"));
        }

        Ok(Self {
            object,
            send_link,
            fork_link,
            exit_link,
            quarantine_links,
            exposures_fd: exposures,
            pending_tgids_fd: pending_tgids,
            quarantine_inodes_fd: quarantine_inodes,
            ring,
            events,
        })
    }

    /// Install containment before the matching `FAN_ACCESS_PERM` event is
    /// allowed. `observe_until_ns` uses the same monotonic clock as BPF's
    /// `bpf_ktime_get_ns`.
    pub fn arm(
        &mut self,
        tgid: u32,
        incident_id: u64,
        uid: u32,
        observe_until_ns: u64,
        state: SshIncidentState,
    ) -> Result<(), String> {
        let value = ExposureValue {
            incident_id,
            observe_until_ns,
            state: match state {
                SshIncidentState::Observing => EXPOSURE_OBSERVING,
                SshIncidentState::PendingDecision | SshIncidentState::BlockedUntilExit => {
                    EXPOSURE_PENDING
                }
                SshIncidentState::Allowed => EXPOSURE_ALLOWED,
                SshIncidentState::Expired
                | SshIncidentState::Quarantined
                | SshIncidentState::Exited => {
                    return Err(format!("cannot arm SSH exposure in {state:?} state"));
                }
            },
            uid,
        };
        let result = unsafe {
            // SAFETY: key/value point to initialized repr(C) data matching the
            // BPF map declaration; the fd belongs to this live object.
            bpf_map_update_elem(
                self.exposures_fd,
                (&tgid as *const u32).cast(),
                (&value as *const ExposureValue).cast(),
                BPF_ANY,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(last_error("arming SSH send containment"))
        }
    }

    /// Allow or remove all known descendants belonging to this incident. The
    /// map is bounded and contains only active exposure processes.
    pub fn resolve(&mut self, incident_id: u64, allow: bool) -> Result<(), String> {
        for (key, mut value) in self.exposures()? {
            if value.incident_id == incident_id {
                let update = if allow {
                    value.state = EXPOSURE_ALLOWED;
                    unsafe {
                        // SAFETY: initialized map key/value as above.
                        bpf_map_update_elem(
                            self.exposures_fd,
                            (&key as *const u32).cast(),
                            (&value as *const ExposureValue).cast(),
                            BPF_ANY,
                        )
                    }
                } else {
                    unsafe {
                        // SAFETY: initialized key as above.
                        bpf_map_delete_elem(self.exposures_fd, (&key as *const u32).cast())
                    }
                };
                if update != 0 {
                    return Err(last_error("resolving SSH send containment"));
                }
                let pending_delete = unsafe {
                    // SAFETY: key points to the same TGID key used by the
                    // kernel-owned pending marker map.
                    bpf_map_delete_elem(self.pending_tgids_fd, (&key as *const u32).cast())
                };
                if pending_delete != 0
                    && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
                {
                    return Err(last_error("clearing pending SSH send containment"));
                }
            }
        }
        Ok(())
    }

    /// Remove observing entries once their bounded correlation window has
    /// elapsed, even if their process never attempts a later send or exits.
    pub fn expire(&mut self, now_ns: u64) -> Result<(), String> {
        for (key, value) in self.exposures()? {
            if value.state == EXPOSURE_OBSERVING
                && now_ns >= value.observe_until_ns
                && !self.is_pending_tgid(key)?
            {
                let result = unsafe {
                    // SAFETY: key points to an initialized map key and this
                    // backend owns the live map fd.
                    bpf_map_delete_elem(self.exposures_fd, (&key as *const u32).cast())
                };
                if result != 0 {
                    return Err(last_error("expiring SSH send containment"));
                }
            }
        }
        Ok(())
    }

    /// Return map entries for which the kernel has already blocked a send.
    /// This is a loss-recovery path for a full ring buffer: enforcement stays
    /// in the kernel, while userspace can still surface the pending incident.
    pub fn pending(&self, at_ns: u64) -> Result<Vec<BlockedSend>, String> {
        let mut pending = Vec::new();
        for (tgid, value) in self.exposures()? {
            if value.state == EXPOSURE_PENDING || self.is_pending_tgid(tgid)? {
                pending.push(BlockedSend {
                    incident_id: value.incident_id,
                    at_ns,
                    tgid,
                    uid: value.uid,
                    size: 0,
                });
            }
        }
        Ok(pending)
    }

    /// Return the current TGIDs that the kernel associates with one incident.
    /// Callers must still pin and independently revalidate every PID before a
    /// lifecycle action; a BPF map is not a permission to signal a naked PID.
    pub fn incident_tgids(&self, incident_id: u64) -> Result<Vec<u32>, String> {
        Ok(self
            .exposures()?
            .into_iter()
            .filter_map(|(tgid, value)| (value.incident_id == incident_id).then_some(tgid))
            .collect())
    }

    pub fn live_incident_ids(&self) -> Result<std::collections::HashSet<u64>, String> {
        Ok(self
            .exposures()?
            .into_iter()
            .map(|(_, value)| value.incident_id)
            .collect())
    }

    /// Prevent every non-daemon LSM caller from renaming, unlinking, linking,
    /// changing attributes, or issuing ordinary writes to this exact inode
    /// while a quarantine transaction verifies and moves it.
    pub fn arm_quarantine_inode(&mut self, dev: u64, ino: u64) -> Result<(), String> {
        let key = InodeKey { dev, ino };
        let value = 1u8;
        let result = unsafe {
            // SAFETY: repr(C) map key/value match the BPF declaration and the
            // map fd belongs to this live backend.
            bpf_map_update_elem(
                self.quarantine_inodes_fd,
                (&key as *const InodeKey).cast(),
                (&value as *const u8).cast(),
                BPF_ANY,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(last_error("arming BPF quarantine inode guard"))
        }
    }

    pub fn disarm_quarantine_inode(&mut self, dev: u64, ino: u64) -> Result<(), String> {
        let key = InodeKey { dev, ino };
        let result = unsafe {
            // SAFETY: repr(C) map key matches the BPF declaration and this
            // backend owns the map fd.
            bpf_map_delete_elem(self.quarantine_inodes_fd, (&key as *const InodeKey).cast())
        };
        if result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(last_error("disarming BPF quarantine inode guard"))
        }
    }

    /// Drain kernel events without blocking the fanotify authorization path.
    pub fn poll(&mut self) -> Result<Vec<BlockedSend>, String> {
        let result = unsafe {
            // SAFETY: ring is live and its callback context remains valid.
            ring_buffer__poll(self.ring, 0)
        };
        if result < 0 {
            return Err(last_error("polling SSH blocked-send events"));
        }
        Ok(std::mem::take(&mut self.events.0))
    }

    /// FD that becomes readable when the ring buffer has a blocked-send event.
    pub fn event_fd(&self) -> c_int {
        unsafe {
            // SAFETY: ring is live for self's lifetime.
            ring_buffer__epoll_fd(self.ring)
        }
    }

    fn exposures(&self) -> Result<Vec<(u32, ExposureValue)>, String> {
        let mut entries = Vec::new();
        let mut previous: Option<u32> = None;
        loop {
            let mut key = 0u32;
            let previous_ptr = previous
                .as_ref()
                .map_or(ptr::null(), |value| (value as *const u32).cast());
            let result = unsafe {
                // SAFETY: next-key storage is valid and the map fd belongs to
                // this backend. A null previous key starts iteration.
                bpf_map_get_next_key(
                    self.exposures_fd,
                    previous_ptr,
                    (&mut key as *mut u32).cast(),
                )
            };
            if result != 0 {
                break;
            }
            let mut value = ExposureValue {
                incident_id: 0,
                observe_until_ns: 0,
                state: 0,
                uid: 0,
            };
            let found = unsafe {
                // SAFETY: key/value storage matches the BPF map declaration.
                bpf_map_lookup_elem(
                    self.exposures_fd,
                    (&key as *const u32).cast(),
                    (&mut value as *mut ExposureValue).cast(),
                )
            };
            if found == 0 {
                entries.push((key, value));
            }
            previous = Some(key);
        }
        Ok(entries)
    }

    fn is_pending_tgid(&self, tgid: u32) -> Result<bool, String> {
        let mut incident_id = 0u64;
        let result = unsafe {
            // SAFETY: key/value storage matches the pending_tgids map.
            bpf_map_lookup_elem(
                self.pending_tgids_fd,
                (&tgid as *const u32).cast(),
                (&mut incident_id as *mut u64).cast(),
            )
        };
        if result == 0 {
            Ok(true)
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(last_error("looking up pending SSH send containment"))
        }
    }
}

impl Drop for SshBehaviorBackend {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: each handle was created by libbpf and is owned solely by
            // this backend. Links detach before object close.
            ring_buffer__free(self.ring);
            for link in self.quarantine_links.drain(..) {
                let _ = bpf_link__destroy(link);
            }
            let _ = bpf_link__destroy(self.exit_link);
            let _ = bpf_link__destroy(self.fork_link);
            let _ = bpf_link__destroy(self.send_link);
            bpf_object__close(self.object);
        }
    }
}

unsafe extern "C" fn receive_event(context: *mut c_void, data: *mut c_void, size: usize) -> c_int {
    if size != size_of::<RawBlockedSend>() || context.is_null() || data.is_null() {
        return 0;
    }
    let mut raw = RawBlockedSend {
        incident_id: 0,
        at_ns: 0,
        tgid: 0,
        uid: 0,
        size: 0,
        _reserved: 0,
    };
    unsafe {
        // SAFETY: libbpf gives a readable `size` byte event and the equality
        // check above proves RawBlockedSend fits exactly.
        ptr::copy_nonoverlapping(data.cast::<RawBlockedSend>(), &mut raw, 1);
        let queue = &mut *(context.cast::<EventQueue>());
        queue.0.push(BlockedSend {
            incident_id: raw.incident_id,
            at_ns: raw.at_ns,
            tgid: raw.tgid,
            uid: raw.uid,
            size: raw.size,
        });
    }
    0
}

fn find_program(object: *mut BpfObject, name: &str) -> Result<*mut BpfProgram, String> {
    let name = CString::new(name).expect("program name has no NUL");
    let program = unsafe {
        // SAFETY: object is live and the string is NUL-terminated for call.
        bpf_object__find_program_by_name(object, name.as_ptr())
    };
    if program.is_null() {
        Err(format!("embedded BPF object is missing program {name:?}"))
    } else {
        Ok(program)
    }
}

fn find_map_fd(object: *mut BpfObject, name: &str) -> Result<c_int, String> {
    let name = CString::new(name).expect("map name has no NUL");
    let map = unsafe {
        // SAFETY: object is live and the string is NUL-terminated for call.
        bpf_object__find_map_by_name(object, name.as_ptr())
    };
    if map.is_null() {
        return Err(format!("embedded BPF object is missing map {name:?}"));
    }
    let fd = unsafe {
        // SAFETY: map belongs to a successfully loaded object.
        bpf_map__fd(map)
    };
    if fd < 0 {
        Err(format!("embedded BPF map {name:?} has no fd"))
    } else {
        Ok(fd)
    }
}

fn destroy_link(link: *mut BpfLink) {
    unsafe {
        // SAFETY: called only with a successfully returned link pointer.
        let _ = bpf_link__destroy(link);
    }
}

fn destroy_links(links: &[*mut BpfLink]) {
    for &link in links {
        destroy_link(link);
    }
}

#[derive(Debug, Clone, Copy)]
struct LibbpfPointerError(c_long);

impl LibbpfPointerError {
    fn context(self, operation: &str) -> String {
        if self.0 < 0 {
            format!(
                "{operation}: {}",
                io::Error::from_raw_os_error((-self.0) as c_int)
            )
        } else {
            format!("{operation}: invalid libbpf pointer ({})", self.0)
        }
    }
}

/// Libbpf uses Linux ERR_PTR values for many fallible pointer-returning APIs;
/// checking only for null could falsely report an unattached hook as active.
fn pointer_error<T>(pointer: *mut T) -> Option<LibbpfPointerError> {
    if pointer.is_null() {
        return Some(LibbpfPointerError(0));
    }
    let error = unsafe {
        // SAFETY: libbpf_get_error accepts either a valid libbpf pointer or
        // one of libbpf's encoded error pointers without dereferencing it.
        libbpf_get_error(pointer.cast())
    };
    (error != 0).then_some(LibbpfPointerError(error))
}

fn last_error(operation: &str) -> String {
    format!("{operation}: {}", io::Error::last_os_error())
}

fn load_error(verifier_log: &[u8], load_error: io::Error) -> String {
    let log = verifier_log
        .split(|byte| *byte == 0)
        .next()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::trim)
        .filter(|log| !log.is_empty())
        .map(|log| {
            const MAX_LOG_CHARS: usize = 8 * 1024;
            if log.len() > MAX_LOG_CHARS {
                format!("{}…", &log[..MAX_LOG_CHARS])
            } else {
                log.to_owned()
            }
        });
    match log {
        Some(log) => format!("loading BPF object: {load_error}; verifier_log={log}"),
        None => format!("loading BPF object: {load_error}"),
    }
}

/// Probe prerequisites without loading a privileged BPF program.
pub fn detect_backend() -> SshBehaviorBackendStatus {
    let lsm = match fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(value) => value,
        Err(error) => {
            return SshBehaviorBackendStatus::Unavailable {
                reason: format!("cannot read active Linux security modules: {error}"),
            }
        }
    };
    if !lsm.trim().split(',').any(|entry| entry == "bpf") {
        return SshBehaviorBackendStatus::Unavailable {
            reason: "BPF LSM is not active. Protected-key access is still reported, but immediate outbound network activity cannot currently be blocked.".into(),
        };
    }
    if !std::path::Path::new("/sys/kernel/btf/vmlinux").is_file() {
        return SshBehaviorBackendStatus::Unavailable {
            reason: "kernel BTF is unavailable for the BPF LSM send hook".into(),
        };
    }
    SshBehaviorBackendStatus::Degraded {
        reason: "BPF LSM prerequisites are present but the send hook is not attached".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_status_is_explicit() {
        assert_eq!(
            SshBehaviorBackendStatus::Unavailable {
                reason: "test".into()
            }
            .label(),
            "UNAVAILABLE"
        );
    }

    #[test]
    fn embedded_bpf_object_is_elf() {
        assert!(EMBEDDED_BPF.starts_with(b"\x7fELF"));
    }

    #[test]
    fn blocked_event_has_stable_kernel_layout() {
        assert_eq!(size_of::<RawBlockedSend>(), 32);
    }

    #[test]
    fn libbpf_open_options_layout_matches_current_api() {
        assert_eq!(size_of::<BpfObjectOpenOpts>(), 88);
    }
}
