//! Narrow macOS platform boundary.
//!
//! Apple framework calls remain in `native/macos`; this crate exposes typed
//! lifecycle and entitlement diagnostics without containing product policy.

pub mod browser_trust;
pub mod bundle;
pub mod code_signature;
pub mod config;
pub mod deadline;
pub mod discovery;
pub mod endpoint_security;
pub mod identity;
pub mod local_auth;
mod pending;
pub mod resource_index;
pub mod system_extension;
pub mod xpc;

pub const DEFAULT_APP_BUNDLE_ID: &str = match option_env!("GUARD_APP_BUNDLE_ID") {
    Some(identifier) => identifier,
    None => "io.github.plfjy.SensitiveFileGuard",
};
pub const DEFAULT_EXTENSION_BUNDLE_ID: &str = match option_env!("GUARD_SYSTEM_EXTENSION_BUNDLE_ID")
{
    Some(identifier) => identifier,
    None => "io.github.plfjy.SensitiveFileGuard.guard-es",
};
pub const DEFAULT_XPC_SERVICE_NAME: &str = match option_env!("GUARD_XPC_SERVICE_NAME") {
    Some(identifier) => identifier,
    None => "io.github.plfjy.SensitiveFileGuard.guard-es.control",
};
