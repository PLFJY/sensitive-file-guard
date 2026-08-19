//! LFH2 Step 3: `FAN_CLASS_NOTIF | FAN_REPORT_FID` topology group (a SEPARATE
//! group from the `FAN_CLASS_CONTENT` permission group — combining
//! `FAN_REPORT_FID` with `FAN_CLASS_CONTENT` is UAPI-forbidden: EINVAL).
//!
//! Purpose: label a NEVER-OPENED dynamic object that moved through a protected
//! tree. `FAN_OPEN_PERM` only labels inodes that were opened under a protected
//! path; a pre-existing/never-seen object renamed outside before any
//! protected-path open would otherwise be invisible. The topology group marks
//! every directory under each enrolled browser root with `FAN_MOVE |
//! FAN_EVENT_ON_CHILD`; a move/rename event carries the moved file's fid. The
//! fid's opaque file handle IS the object's identity, so we learn it directly
//! into a handle-only protected index (no `open_by_handle_at`, no inode
//! resolution — that syscall's semantics differ across kernels and are not
//! required for the guarantee). Any later open of the same object (at any
//! path) computes the event fd's handle and matches it → Protected → an
//! unknown reader is denied. Inode reuse is a non-issue: a reused inode has a
//! different handle and does not match.
//!
//! The permission gate for that later open is strict mode's
//! `FAN_MARK_FILESYSTEM | FAN_OPEN_PERM` mark; NO inode-level
//! `FAN_OPEN_PERM` mark is added here. An extra inode mark would double-fire
//! permission events for the same open (the first response consumes the event
//! and the second is EINVAL, breaking the response loop and hanging the
//! opener) and grow marks without bound as browsers move files.
//!
//! Race-safe fallback: Guard never assumes an ordering between the topology
//! group and the permission group. The learned handle makes classification
//! deterministic; the fs-wide permission mark makes the gate fire. Both are in
//! place once the (FIFO) topology event is processed; the acceptance test
//! settles after the rename so processing completes before the reader opens.
//! The residual sub-queue-latency window (a reader opening between the rename
//! syscall and the daemon processing the topology event) is documented as a
//! REDUCED limitation, not claimed closed.

use std::path::Path;
use std::sync::Arc;

use platform_linux::fanotify::{self, FidEvent, FAN_MOVE_EVENTS};

use crate::enforce::EnforcementMode;
use crate::strict::StrictClassifier;

pub struct TopologyLearner {
    /// The `FAN_CLASS_NOTIF | FAN_REPORT_FID` group (notifications only).
    topology: Arc<fanotify::FanotifyGroup>,
    classifier: Arc<StrictClassifier>,
}

impl TopologyLearner {
    /// Create the learner. Requires strict mode (the strict classifier owns
    /// the learned-handle index); conservative mode intentionally keeps the
    /// never-opened dynamic-object story REDUCED.
    pub fn new(
        mode: EnforcementMode,
        classifier: Arc<StrictClassifier>,
        topology: Arc<fanotify::FanotifyGroup>,
    ) -> anyhow::Result<Self> {
        if mode != EnforcementMode::StrictFilesystem {
            anyhow::bail!("topology learner requires strict-filesystem mode");
        }
        Ok(Self {
            topology,
            classifier,
        })
    }

    /// LFH2 Step 3 pre-existing snapshot (passthrough to the strict
    /// classifier's learned-handle index).
    pub fn classifier_snapshot_dynamic_handles(&self) -> usize {
        self.classifier.snapshot_dynamic_handles()
    }

    /// Recursively mark every directory under each browser root with
    /// `FAN_MOVE | FAN_EVENT_ON_CHILD` so moves/renames of any child file
    /// (at any depth) generate a FID event.
    pub fn mark_trees(&self) -> std::io::Result<usize> {
        let mut n = 0;
        for root in self.classifier.topology_roots() {
            n += mark_dir_recursive(self.topology.as_ref(), &root)?;
        }
        Ok(n)
    }

    /// Drain the topology group and learn moved objects. Blocks with a
    /// bounded poll so shutdown is prompt.
    pub fn run(&self) {
        tracing::info!("topology learner thread started");
        let mut buf = vec![0u8; 65536];
        loop {
            if crate::signal::is_shutdown() {
                break;
            }
            let ready = unsafe {
                let mut pfd = libc::pollfd {
                    fd: self.topology.raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                libc::poll(&mut pfd, 1, 250)
            };
            if ready < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EINTR) {
                    tracing::error!(%err, "topology poll failed");
                }
                continue;
            }
            if ready == 0 {
                continue;
            }
            let n = match self.topology.read(&mut buf) {
                Ok(n) => n,
                Err(error) => {
                    tracing::warn!(%error, "topology read failed");
                    continue;
                }
            };
            let events = match fanotify::parse_fid_events(&buf[..n]) {
                Ok(events) => events,
                Err(error) => {
                    tracing::error!(%error, "topology event parse failed closed");
                    continue;
                }
            };
            for event in events {
                self.handle_move_event(&event);
            }
        }
    }

    fn handle_move_event(&self, event: &FidEvent) {
        if event.overflow {
            tracing::warn!("topology group overflow; a move may have been missed (REDUCED)");
            return;
        }
        if event.mask & FAN_MOVE_EVENTS == 0 {
            return;
        }
        // Learn ONLY from MOVED_TO (a file entering a marked tree). The
        // MOVED_TO event's fid IS the moved FILE's handle (verified against
        // the kernel); the MOVED_FROM event's fid is the SOURCE DIRECTORY's
        // handle and is useless for the file's identity. Pre-existing objects
        // are covered by the startup snapshot, and objects that entered a tree
        // are learned here, so any later rename-out is recognized.
        if event.mask & libc::FAN_MOVED_TO == 0 {
            return;
        }
        let Some(fid) = &event.fid else {
            return;
        };
        if fid.handle_bytes.is_empty() {
            return;
        }
        // The fid's opaque handle IS the object identity: learn it directly
        // into the handle-only index. No inode resolution, no open_by_handle_at.
        let resource = self.classifier.fallback_dynamic_resource();
        self.classifier
            .learn_topology_handle(fid.handle_type, fid.handle_bytes.clone(), resource);
        tracing::info!(
            handle_type = fid.handle_type,
            handle_bytes = format_args!("{:02x?}", fid.handle_bytes),
            mask = format_args!("0x{:x}", event.mask),
            "topology: learned never-opened dynamic object handle"
        );
    }
}

fn mark_dir_recursive(group: &fanotify::FanotifyGroup, dir: &Path) -> std::io::Result<usize> {
    let mut n = 0;
    group.mark_dir_move(dir)?;
    n += 1;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            n += mark_dir_recursive(group, &entry.path())?;
        }
    }
    Ok(n)
}
