//! Narrow macOS platform boundary.
//!
//! Apple framework calls remain in `native/macos`; this crate exposes typed
//! lifecycle and entitlement diagnostics without containing product policy.

#[cfg(target_os = "macos")]
pub mod browser_session;
#[cfg(target_os = "macos")]
pub mod browser_trust;
#[cfg(target_os = "macos")]
pub mod bundle;
#[cfg(target_os = "macos")]
pub mod code_signature;
#[cfg(target_os = "macos")]
pub mod config;
#[cfg(target_os = "macos")]
pub mod deadline;
#[cfg(target_os = "macos")]
pub mod discovery;
#[cfg(target_os = "macos")]
pub mod endpoint_security;
#[cfg(target_os = "macos")]
pub mod identity;
#[cfg(target_os = "macos")]
pub mod local_auth;
#[cfg(target_os = "macos")]
pub mod notifications;
#[cfg(target_os = "macos")]
mod pending;
#[cfg(target_os = "macos")]
pub mod process_shield;
#[cfg(target_os = "macos")]
pub mod resource_index;
#[cfg(target_os = "macos")]
pub mod system_extension;
#[cfg(target_os = "macos")]
pub mod user_agent;
#[cfg(target_os = "macos")]
pub mod xpc;

pub const DEFAULT_APP_BUNDLE_ID: &str = match option_env!("GUARD_APP_BUNDLE_ID") {
    Some(identifier) => identifier,
    None => "top.plfjy.SensitiveFileGuard",
};
pub const DEFAULT_EXTENSION_BUNDLE_ID: &str = match option_env!("GUARD_SYSTEM_EXTENSION_BUNDLE_ID")
{
    Some(identifier) => identifier,
    None => "top.plfjy.SensitiveFileGuard.guard-es",
};
pub const DEFAULT_XPC_SERVICE_NAME: &str = match option_env!("GUARD_XPC_SERVICE_NAME") {
    Some(identifier) => identifier,
    None => "top.plfjy.SensitiveFileGuard.guard-es.control",
};
pub const DEFAULT_USER_AGENT_PLIST_NAME: &str = match option_env!("GUARD_USER_AGENT_PLIST_NAME") {
    Some(name) => name,
    None => "top.plfjy.SensitiveFileGuard.guard-notify.plist",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_product_identifiers_use_top_plfjy_namespace() {
        for identifier in [
            DEFAULT_APP_BUNDLE_ID,
            DEFAULT_EXTENSION_BUNDLE_ID,
            DEFAULT_XPC_SERVICE_NAME,
            DEFAULT_USER_AGENT_PLIST_NAME,
        ] {
            assert!(
                identifier.starts_with("top.plfjy."),
                "non-current macOS product identifier: {identifier}"
            );
        }
        assert_eq!(
            DEFAULT_EXTENSION_BUNDLE_ID,
            format!("{DEFAULT_APP_BUNDLE_ID}.guard-es")
        );
        assert_eq!(
            DEFAULT_XPC_SERVICE_NAME,
            format!("{DEFAULT_EXTENSION_BUNDLE_ID}.control")
        );
        assert_eq!(
            DEFAULT_USER_AGENT_PLIST_NAME,
            format!("{DEFAULT_APP_BUNDLE_ID}.guard-notify.plist")
        );
    }
}
