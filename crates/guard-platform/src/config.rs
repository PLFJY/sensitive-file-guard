//! Portable policy/configuration models.

use std::path::PathBuf;

use guard_core::resource::{BrowserFamily, ProtectedResourceKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BrowserProtectionLevel {
    #[default]
    Common,
    Strict,
}

impl BrowserProtectionLevel {
    pub fn protects(self, kind: ProtectedResourceKind) -> bool {
        match kind {
            ProtectedResourceKind::CookieStore
            | ProtectedResourceKind::SavedCredentials
            | ProtectedResourceKind::BrowserKeyMaterial => true,
            ProtectedResourceKind::WebStorage => self == Self::Strict,
            ProtectedResourceKind::SshPrivateKey | ProtectedResourceKind::Other => false,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Common => "common",
            Self::Strict => "strict",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "common" => Some(Self::Common),
            "strict" => Some(Self::Strict),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrowserEnrollmentConfig {
    pub id: String,
    pub family: BrowserFamily,
    pub profile_root: PathBuf,
    #[serde(default)]
    pub owner_uid: Option<u32>,
    #[serde(default)]
    pub exe_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub browser_protection_level: BrowserProtectionLevel,
    pub browsers: Vec<BrowserEnrollmentConfig>,
    #[serde(default)]
    pub enrolled_exes: Vec<PathBuf>,
    #[serde(default)]
    pub ssh_keys: Vec<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_protection_level_matrix_is_credential_scoped() {
        for kind in [
            ProtectedResourceKind::CookieStore,
            ProtectedResourceKind::SavedCredentials,
            ProtectedResourceKind::BrowserKeyMaterial,
        ] {
            assert!(BrowserProtectionLevel::Common.protects(kind));
            assert!(BrowserProtectionLevel::Strict.protects(kind));
        }
        assert!(!BrowserProtectionLevel::Common.protects(ProtectedResourceKind::WebStorage));
        assert!(BrowserProtectionLevel::Strict.protects(ProtectedResourceKind::WebStorage));
        assert!(!BrowserProtectionLevel::Common.protects(ProtectedResourceKind::SshPrivateKey));
        assert!(!BrowserProtectionLevel::Strict.protects(ProtectedResourceKind::Other));
    }

    #[test]
    fn missing_level_defaults_to_common() {
        let config: PolicyConfig = serde_json::from_str(
            r#"{"browsers":[],"enrolled_exes":["/synthetic/exe"],"ssh_keys":[]}"#,
        )
        .unwrap();
        assert_eq!(
            config.browser_protection_level,
            BrowserProtectionLevel::Common
        );
    }

    #[test]
    fn policy_config_rejects_unknown_fields() {
        assert!(serde_json::from_str::<PolicyConfig>(
            r#"{"browser_protection_level":"common","browsers":[],"enrolled_exes":[],"ssh_keys":[],"unexpected_option":true}"#,
        )
        .is_err());
    }
}

impl PolicyConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.browsers.is_empty() && self.ssh_keys.is_empty() && self.enrolled_exes.is_empty() {
            anyhow::bail!("configuration must enroll at least one browser or SSH key");
        }
        for browser in &self.browsers {
            if browser.id.trim().is_empty() {
                anyhow::bail!("browser id must not be empty");
            }
            if !browser.profile_root.is_absolute() {
                anyhow::bail!("browser {} profile_root must be absolute", browser.id);
            }
            for exe in &browser.exe_paths {
                if !exe.is_absolute() {
                    anyhow::bail!("browser {} executable must be absolute", browser.id);
                }
            }
        }
        for path in self.ssh_keys.iter().chain(self.enrolled_exes.iter()) {
            if !path.is_absolute() {
                anyhow::bail!("configured path must be absolute: {}", path.display());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserSuggestion {
    pub id: String,
    pub family: BrowserFamily,
    pub profile_root: PathBuf,
    pub exe_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsupportedSandboxedBrowser {
    pub kind: String,
    pub profile_root: PathBuf,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserDiscovery {
    pub browsers: Vec<BrowserSuggestion>,
    pub unsupported_sandboxed: Vec<UnsupportedSandboxedBrowser>,
}
