//! Linux platform interception layer.
//!
//! Phase 02: fanotify permission-event interception (`FAN_OPEN_PERM`), the
//! privileged `guardd` data plane, capability detection, and minimal `/proc`
//! helpers. Phase 04 adds full process identity resolution and trust tiers.

pub mod capability;
pub mod enrollment;
pub mod fanotify;
pub mod identity;
pub mod ipc;
pub mod proc;
pub mod signal;
pub mod topology;
