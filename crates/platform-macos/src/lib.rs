//! Narrow macOS platform boundary.
//!
//! Apple framework calls remain in `native/macos`; this crate exposes typed
//! lifecycle and entitlement diagnostics without containing product policy.

pub mod bundle;
pub mod deadline;
pub mod endpoint_security;
mod pending;
pub mod system_extension;

pub const DEFAULT_APP_BUNDLE_ID: &str = "io.github.plfjy.SensitiveFileGuard";
pub const DEFAULT_EXTENSION_BUNDLE_ID: &str = "io.github.plfjy.SensitiveFileGuard.guard-es";
