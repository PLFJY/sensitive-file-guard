//! Linux platform interception layer.
//!
//! Phase 02: fanotify permission-event interception (`FAN_OPEN_PERM`), the
//! privileged `guardd` data plane, capability detection, and minimal `/proc`
//! helpers. Phase 04 adds full process identity resolution and trust tiers.

#[cfg(target_os = "linux")]
pub mod capability;
#[cfg(target_os = "linux")]
pub mod config;
#[cfg(target_os = "linux")]
pub mod enrollment;
#[cfg(target_os = "linux")]
pub mod fanotify;
#[cfg(target_os = "linux")]
pub mod identity;
#[cfg(target_os = "linux")]
pub mod ipc;
pub mod object_handle;
#[cfg(target_os = "linux")]
pub mod proc;
#[cfg(target_os = "linux")]
pub mod service;
#[cfg(target_os = "linux")]
pub mod signal;
#[cfg(target_os = "linux")]
pub mod topology;
