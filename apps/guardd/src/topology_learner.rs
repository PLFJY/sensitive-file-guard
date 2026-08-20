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
//! Cross-group ordering (R1): the permission hot path must never assume the
//! background learner processed a move before the corresponding open arrives.
//! The learner and the permission hot path therefore drain the SAME topology
//! queue under the SAME mutex (`StrictClassifier::drain_topology_events`):
//! read→parse→publish is atomic, so there is no "event consumed but handle
//! not yet published" window, and a synchronous drain at decision time
//! processes every topology event enqueued before the open's permission event
//! (syscall order ⇒ enqueue order across groups). This thread is only the
//! background drain (250 ms cadence); the hot-path drain provides the
//! zero-settle guarantee.
//!
//! Runtime-created subdirectories (R1): directory marks are per-directory, so
//! a subdirectory created after startup is not watched. This thread refreshes
//! the tree marks on a bounded cadence (every 2 s) so newly created
//! subdirectories are marked; the window between creation and the next refresh
//! is a documented REDUCED gap for objects moving through a brand-new dir.

use std::path::Path;
use std::sync::Arc;

use platform_linux::fanotify;

use crate::enforce::EnforcementMode;
use crate::strict::StrictClassifier;

pub struct TopologyLearner {
    /// The `FAN_CLASS_NOTIF | FAN_REPORT_FID` group (notifications only).
    topology: Arc<fanotify::FanotifyGroup>,
    classifier: Arc<StrictClassifier>,
    /// Directories already marked for `FAN_MOVE` (avoids re-marking on every
    /// refresh cycle). Includes the startup recursive walk.
    marked: std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>>,
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
            marked: std::sync::Mutex::new(std::collections::HashSet::new()),
        })
    }

    /// LFH2 Step 3 pre-existing snapshot (passthrough to the strict
    /// classifier's learned-handle index).
    pub fn classifier_snapshot_dynamic_handles(&self) -> usize {
        self.classifier.snapshot_dynamic_handles()
    }

    /// Recursively mark every directory under each browser root with
    /// `FAN_MOVE | FAN_EVENT_ON_CHILD` so moves/renames of any child file
    /// (at any depth) generate a FID event. Records the marked set so the
    /// periodic refresh only marks NEW directories.
    pub fn mark_trees(&self) -> std::io::Result<usize> {
        let mut n = 0;
        let mut marked = self.marked.lock().expect("marked set lock poisoned");
        for root in self.classifier.topology_roots() {
            n += mark_dir_recursive(
                self.topology.as_ref(),
                self.classifier.as_ref(),
                &root,
                &mut marked,
            )?;
        }
        Ok(n)
    }

    /// Drain the topology group (shared mutex with the permission hot path)
    /// and periodically refresh tree marks so runtime-created subdirectories
    /// are watched. Bounded sleeps keep shutdown prompt.
    pub fn run(&self) {
        tracing::info!("topology learner thread started");
        let mut cycle = 0u32;
        loop {
            if crate::signal::is_shutdown() {
                break;
            }
            // Background drain: same mutex + same code path as the permission
            // hot path's synchronous drain, so consumed events are always
            // published before the lock is released.
            self.classifier.drain_topology_events();
            // R1: refresh marks every ~2 s (8 × 250 ms) so a subdirectory
            // created after startup becomes watched without a restart.
            cycle = cycle.wrapping_add(1);
            if cycle.is_multiple_of(8) {
                if let Err(error) = self.refresh_tree_marks() {
                    // A refresh error includes a missing live mark. The
                    // in-memory set is only an intent log, not evidence that
                    // the kernel still delivers move events.
                    self.classifier.mark_topology_uncertain();
                    tracing::error!(%error, "topology tree-mark refresh failed; topology identity UNCERTAIN, ambiguous opens fail closed");
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    /// R1: re-walk the protected trees and mark any directory created since
    /// the last refresh (or the startup walk). Bounded REDUCED window between
    /// a subdirectory's creation and its mark is inherent to the cadence.
    fn refresh_tree_marks(&self) -> std::io::Result<usize> {
        let mut n = 0;
        let mut marked = self.marked.lock().expect("marked set lock poisoned");
        // This group owns only directory move marks. If the kernel no longer
        // reports every mark we installed, a move may have been missed; do
        // not silently trust the bookkeeping set or classify outside objects
        // as unrelated.
        let observed = self.topology.mark_count()?;
        if observed < marked.len() {
            return Err(std::io::Error::other(format!(
                "topology mark loss: observed {observed} live marks, expected at least {}",
                marked.len()
            )));
        }
        for root in self.classifier.topology_roots() {
            n += mark_dir_recursive(
                self.topology.as_ref(),
                self.classifier.as_ref(),
                &root,
                &mut marked,
            )?;
        }
        if n > 0 {
            tracing::info!(
                new_dirs = n,
                "topology: marked newly created subdirectories"
            );
        }
        Ok(n)
    }
}

fn mark_dir_recursive(
    group: &fanotify::FanotifyGroup,
    classifier: &StrictClassifier,
    dir: &Path,
    marked: &mut std::collections::HashSet<std::path::PathBuf>,
) -> std::io::Result<usize> {
    let mut n = 0;
    if !marked.contains(dir) {
        group.mark_dir_move(dir)?;
        // Record the dir's handle so move events' parent handles (the fid is
        // the parent dir on kernel 7.1, never the moved file) resolve back
        // to a path for `parent/name` identity resolution.
        classifier.record_marked_dir(dir);
        // Insert only after the kernel accepted the mark. Otherwise a retry
        // would be skipped even though this directory was never covered.
        marked.insert(dir.to_path_buf());
        n += 1;
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            n += mark_dir_recursive(group, classifier, &entry.path(), marked)?;
        }
    }
    Ok(n)
}
