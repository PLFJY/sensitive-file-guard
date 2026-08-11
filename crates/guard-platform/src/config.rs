//! Portable policy/configuration models.

use std::path::PathBuf;

use guard_core::resource::BrowserFamily;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementMode {
    #[default]
    Conservative,
    StrictFilesystem,
}

impl EnforcementMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::StrictFilesystem => "strict-filesystem",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
pub struct EnforcementConfig {
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,
    pub browsers: Vec<BrowserEnrollmentConfig>,
    #[serde(default)]
    pub enrolled_exes: Vec<PathBuf>,
    #[serde(default)]
    pub ssh_keys: Vec<PathBuf>,
}

impl EnforcementConfig {
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
            if self.enforcement_mode == EnforcementMode::StrictFilesystem
                && !browser.profile_root.is_dir()
            {
                anyhow::bail!(
                    "browser {} profile root does not exist: {}",
                    browser.id,
                    browser.profile_root.display()
                );
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
