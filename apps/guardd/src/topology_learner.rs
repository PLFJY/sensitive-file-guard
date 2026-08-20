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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use platform_linux::fanotify;

use crate::enforce::EnforcementMode;
use crate::strict::StrictClassifier;

pub struct TopologyLearner {
    /// The `FAN_CLASS_NOTIF | FAN_REPORT_FID` group (notifications only).
    topology: Arc<fanotify::FanotifyGroup>,
    classifier: Arc<StrictClassifier>,
    /// Live directory marks keyed by path and the opaque identity present when
    /// the mark was installed. A path alone is not stable: an intentionally
    /// deleted runtime directory can later be recreated with a new inode.
    marked: std::sync::Mutex<HashMap<PathBuf, platform_linux::object_handle::ObjectHandle>>,
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
            marked: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// LFH2 Step 3 pre-existing snapshot (passthrough to the strict
    /// classifier's learned-handle index).
    pub fn classifier_snapshot_dynamic_handles(&self) -> usize {
        self.classifier.snapshot_dynamic_handles()
    }

    /// Mark every live directory under each browser root with `FAN_MOVE |
    /// FAN_EVENT_ON_CHILD`. Initial setup has no prior live mark set to audit;
    /// later refreshes reconcile path *and object identity* before marking new
    /// or recreated directories.
    pub fn mark_trees(&self) -> std::io::Result<usize> {
        let desired = self.desired_live_dirs()?;
        let mut marked = self.marked.lock().expect("marked set lock poisoned");
        reconcile_tree_marks(
            self.topology.as_ref(),
            self.classifier.as_ref(),
            &desired,
            &mut marked,
            None,
        )
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

    /// Reconcile kernel topology marks with the desired live directory set.
    /// Intentionally deleted directories are removed from the expected live
    /// set, while a same-path/new-object directory is marked anew. A count
    /// shortfall for still-live identities is an unexpected mark loss and is
    /// returned to the caller to make topology UNCERTAIN sticky.
    fn refresh_tree_marks(&self) -> std::io::Result<usize> {
        let desired = self.desired_live_dirs()?;
        let mut marked = self.marked.lock().expect("marked set lock poisoned");
        let observed = self.topology.mark_count()?;
        let n = reconcile_tree_marks(
            self.topology.as_ref(),
            self.classifier.as_ref(),
            &desired,
            &mut marked,
            Some(observed),
        )?;
        if n > 0 {
            tracing::info!(
                new_dirs = n,
                "topology: marked newly created subdirectories"
            );
        }
        Ok(n)
    }

    fn desired_live_dirs(
        &self,
    ) -> std::io::Result<HashMap<PathBuf, platform_linux::object_handle::ObjectHandle>> {
        let mut desired = HashMap::new();
        for root in self.classifier.topology_roots() {
            collect_live_dirs(&root, &mut desired)?;
        }
        Ok(desired)
    }
}

/// Reconcile directory mark intent with live directory identities. `observed`
/// is absent during startup, when no prior mark can have been lost.
fn reconcile_tree_marks(
    group: &fanotify::FanotifyGroup,
    classifier: &StrictClassifier,
    desired: &HashMap<PathBuf, platform_linux::object_handle::ObjectHandle>,
    marked: &mut HashMap<PathBuf, platform_linux::object_handle::ObjectHandle>,
    observed: Option<usize>,
) -> std::io::Result<usize> {
    let (retained, stale_paths, missing_paths) = mark_intent_delta(desired, marked);
    if let Some(observed) = observed {
        // The topology group owns only these directory marks. Removed paths
        // are deliberately excluded: their kernel marks may have disappeared
        // normally with the directory, and must not make uncertainty sticky.
        if observed_mark_count_is_insufficient(observed, retained) {
            return Err(std::io::Error::other(format!(
                "topology mark loss: observed {observed} marks, expected at least {retained} for live directory identities"
            )));
        }
    }

    for path in stale_paths {
        marked.remove(&path);
        classifier.forget_marked_dir(&path);
    }

    let mut added = 0;
    for path in missing_paths {
        let expected_identity = desired
            .get(&path)
            .expect("missing path must have a desired identity");
        let installed_identity = mark_live_dir(group, classifier, &path, expected_identity)?;
        marked.insert(path, installed_identity);
        added += 1;
    }
    Ok(added)
}

/// Mark a directory and confirm that the marked object is still the object at
/// the pathname. If an unlink/recreate race occurs between enumeration and
/// `fanotify_mark`, repeat once for the newly observed identity. This keeps a
/// normal delete/recreate lifecycle from becoming a false permanent topology
/// loss while still failing closed if the path will not stabilize.
fn mark_live_dir(
    group: &fanotify::FanotifyGroup,
    classifier: &StrictClassifier,
    path: &Path,
    expected_identity: &platform_linux::object_handle::ObjectHandle,
) -> std::io::Result<platform_linux::object_handle::ObjectHandle> {
    let mut expected_identity = expected_identity.clone();
    for attempt in 0..2 {
        group.mark_dir_move(path)?;
        let installed_identity = classifier.record_marked_dir(path)?;
        if installed_identity == expected_identity {
            return Ok(installed_identity);
        }
        // The mark just installed may belong to the old object; retry against
        // the newly observed object rather than recording a false live mark.
        expected_identity = installed_identity;
        if attempt == 1 {
            return Err(std::io::Error::other(format!(
                "directory identity kept changing while installing topology mark: {}",
                path.display()
            )));
        }
    }
    unreachable!("two attempts either return or fail")
}

/// Compute which prior marks are still evidence for the current live tree.
/// A recreated pathname is deliberately both stale (its old identity must be
/// forgotten) and missing (the new identity needs a fresh kernel mark).
fn mark_intent_delta(
    desired: &HashMap<PathBuf, platform_linux::object_handle::ObjectHandle>,
    marked: &HashMap<PathBuf, platform_linux::object_handle::ObjectHandle>,
) -> (usize, Vec<PathBuf>, Vec<PathBuf>) {
    let retained = marked
        .iter()
        .filter(|(path, identity)| desired.get(*path) == Some(*identity))
        .count();
    let stale = marked
        .iter()
        .filter(|(path, identity)| desired.get(*path) != Some(*identity))
        .map(|(path, _)| path.clone())
        .collect();
    let missing = desired
        .iter()
        .filter(|(path, identity)| marked.get(*path) != Some(*identity))
        .map(|(path, _)| path.clone())
        .collect();
    (retained, stale, missing)
}

fn observed_mark_count_is_insufficient(observed: usize, retained: usize) -> bool {
    observed < retained
}

fn collect_live_dirs(
    dir: &Path,
    desired: &mut HashMap<PathBuf, platform_linux::object_handle::ObjectHandle>,
) -> std::io::Result<()> {
    let c_path = std::ffi::CString::new(dir.to_string_lossy().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: O_PATH observes directory identity without reading its contents.
    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let identity = platform_linux::object_handle::ObjectHandle::from_fd(fd);
    unsafe { libc::close(fd) };
    desired.insert(dir.to_path_buf(), identity?);
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            collect_live_dirs(&entry.path(), desired)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(byte: u8) -> platform_linux::object_handle::ObjectHandle {
        platform_linux::object_handle::ObjectHandle {
            mount_id: 1,
            handle_type: 1,
            handle_bytes: vec![byte],
        }
    }

    #[test]
    fn recreated_path_is_not_treated_as_the_deleted_directory() {
        let old_path = PathBuf::from("/synthetic/profile/runtime");
        let marked = HashMap::from([(old_path.clone(), handle(1))]);
        let desired = HashMap::from([(old_path.clone(), handle(2))]);

        let (retained, stale, missing) = mark_intent_delta(&desired, &marked);
        assert_eq!(retained, 0, "new object must not inherit old mark intent");
        assert_eq!(stale, vec![old_path.clone()]);
        assert_eq!(missing, vec![old_path]);
    }

    #[test]
    fn missing_mark_for_a_live_identity_is_detectable() {
        let retained_live_marks = 3usize;
        let observed = 2usize;
        assert!(observed_mark_count_is_insufficient(
            observed,
            retained_live_marks
        ));
    }
}
