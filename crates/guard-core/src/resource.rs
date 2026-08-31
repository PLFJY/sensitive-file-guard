//! Protected-resource domain types.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The kind of protected resource. Drives the policy branch (browser vs SSH).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtectedResourceKind {
    CookieStore,
    BrowserKeyMaterial,
    WebStorage,
    SavedCredentials,
    SshPrivateKey,
    Other,
}

impl ProtectedResourceKind {
    pub fn is_browser(&self) -> bool {
        matches!(
            self,
            Self::CookieStore
                | Self::BrowserKeyMaterial
                | Self::WebStorage
                | Self::SavedCredentials
        )
    }
    pub fn is_ssh(&self) -> bool {
        matches!(self, Self::SshPrivateKey)
    }
    pub fn is_critical_browser(&self) -> bool {
        matches!(
            self,
            Self::CookieStore | Self::SavedCredentials | Self::BrowserKeyMaterial
        )
    }
    /// Stable, machine-readable snake_case kind code for tools (Phase 12).
    /// Exposed via `guardctl explain --json` as `resource_kind_code`. These
    /// strings are a public contract — add new codes, do not rename.
    pub fn kind_code(&self) -> &'static str {
        match self {
            Self::CookieStore => "browser_cookie_store",
            Self::BrowserKeyMaterial => "browser_key_material",
            Self::WebStorage => "browser_web_storage",
            Self::SavedCredentials => "browser_saved_credentials",
            Self::SshPrivateKey => "ssh_private_key",
            Self::Other => "other",
        }
    }
}

/// High-level browser family, used by discovery classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BrowserFamily {
    #[serde(alias = "chromium")]
    Chromium,
    #[serde(alias = "firefox")]
    Firefox,
    /// Firefox-derived (e.g. Zen).
    #[serde(alias = "zen")]
    Zen,
    /// Safari is macOS-only and uses a dedicated WebKit data layout.
    #[serde(alias = "safari")]
    Safari,
}

/// Stable identifier for a browser install/profile family (e.g. "chrome",
/// "firefox", "brave"). Not a process name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BrowserId(pub String);

/// Identifier for a browser profile within a browser (e.g. "Default",
/// "Profile 1", or a Firefox profile dir name).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProfileId(pub String);

/// Stable identifier for a protected resource instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtectedResourceId(pub String);

/// A concrete protected resource discovered/enrolled by the daemon.
///
/// `owner_uid` is the OS user who owns the profile/key; the policy uses it to
/// reject cross-user access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResource {
    pub id: ProtectedResourceId,
    pub kind: ProtectedResourceKind,
    pub owner_uid: u32,
    /// Owning browser for browser resources; `None` for SSH keys.
    pub browser: Option<BrowserId>,
    /// Owning profile for browser resources; `None` for SSH keys.
    pub profile: Option<ProfileId>,
    pub path: PathBuf,
}

impl ProtectedResource {
    pub fn browser_id(&self) -> &BrowserId {
        self.browser
            .as_ref()
            .expect("browser_id called on non-browser resource")
    }
    pub fn profile_id(&self) -> &ProfileId {
        self.profile
            .as_ref()
            .expect("profile_id called on resource without profile")
    }
}
