//! Shared public Linux configuration and native browser suggestions.
//!
//! This module intentionally contains data validation and discovery only.  It
//! does not decide whether a process may open a resource; that remains in the
//! daemon enforcement engine.

use std::path::{Path, PathBuf};

use guard_core::resource::{BrowserFamily, BrowserId};
pub use guard_platform::config::{
    BrowserDiscovery, BrowserEnrollmentConfig, BrowserSuggestion, PolicyConfig,
    UnsupportedSandboxedBrowser,
};
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

/// Linux composition configuration. The flattened shape preserves existing
/// `/etc/guardd/config.json` files while keeping backend mode out of portable
/// policy configuration.
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
    pub fn policy(&self) -> PolicyConfig {
        PolicyConfig {
            browsers: self.browsers.clone(),
            enrolled_exes: self.enrolled_exes.clone(),
            ssh_keys: self.ssh_keys.clone(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        self.policy().validate()?;
        if self.enforcement_mode == EnforcementMode::StrictFilesystem {
            for browser in &self.browsers {
                if !browser.profile_root.is_dir() {
                    anyhow::bail!(
                        "browser {} profile root does not exist: {}",
                        browser.id,
                        browser.profile_root.display()
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NativeBrowserLayout {
    pub id: &'static str,
    pub family: BrowserFamily,
    pub profile_relative: &'static str,
    pub executable_candidates: &'static [&'static str],
}

pub const NATIVE_BROWSER_LAYOUTS: &[NativeBrowserLayout] = &[
    NativeBrowserLayout {
        id: "firefox",
        family: BrowserFamily::Firefox,
        profile_relative: ".mozilla/firefox",
        executable_candidates: &["/usr/lib/firefox/firefox", "/usr/lib64/firefox/firefox"],
    },
    NativeBrowserLayout {
        id: "firefox-esr",
        family: BrowserFamily::Firefox,
        profile_relative: ".mozilla/firefox-esr",
        executable_candidates: &[
            "/usr/lib/firefox-esr/firefox-esr",
            "/usr/lib64/firefox-esr/firefox-esr",
        ],
    },
    NativeBrowserLayout {
        id: "zen",
        family: BrowserFamily::Zen,
        profile_relative: ".zen",
        executable_candidates: &[
            "/usr/lib/zen-browser/zen",
            "/usr/lib/zen/zen",
            "/opt/zen-browser/zen",
        ],
    },
    NativeBrowserLayout {
        id: "chromium",
        family: BrowserFamily::Chromium,
        profile_relative: ".config/chromium",
        executable_candidates: &[
            "/usr/lib/chromium/chromium",
            "/usr/lib/chromium-browser/chromium-browser",
            "/usr/lib64/chromium-browser/chromium-browser",
        ],
    },
    NativeBrowserLayout {
        id: "google-chrome",
        family: BrowserFamily::Chromium,
        profile_relative: ".config/google-chrome",
        executable_candidates: &["/opt/google/chrome/chrome"],
    },
    NativeBrowserLayout {
        id: "brave",
        family: BrowserFamily::Chromium,
        profile_relative: ".config/BraveSoftware/Brave-Browser",
        executable_candidates: &["/opt/brave.com/brave/brave"],
    },
    NativeBrowserLayout {
        id: "microsoft-edge",
        family: BrowserFamily::Chromium,
        profile_relative: ".config/microsoft-edge",
        executable_candidates: &["/opt/microsoft/msedge/msedge"],
    },
    NativeBrowserLayout {
        id: "opera",
        family: BrowserFamily::Chromium,
        profile_relative: ".config/opera",
        executable_candidates: &[
            "/usr/lib/opera/opera",
            "/usr/lib64/opera/opera",
            "/opt/opera/opera",
        ],
    },
    NativeBrowserLayout {
        id: "vivaldi",
        family: BrowserFamily::Chromium,
        profile_relative: ".config/vivaldi",
        executable_candidates: &["/opt/vivaldi/vivaldi"],
    },
];

pub fn discover_native_browsers(home: &Path) -> BrowserDiscovery {
    discover_native_browsers_with_layouts(home, NATIVE_BROWSER_LAYOUTS)
}

/// Linux adapter for the portable browser-discovery seam. Linux filesystem
/// layouts are kept here rather than in GTK or product policy crates.
pub struct LinuxBrowserDiscovery;

impl guard_platform::BrowserDiscovery for LinuxBrowserDiscovery {
    fn discover(&self, home: &Path) -> BrowserDiscovery {
        discover_native_browsers(home)
    }
}

pub fn discover_native_browsers_with_layouts(
    home: &Path,
    layouts: &[NativeBrowserLayout],
) -> BrowserDiscovery {
    let mut browsers = Vec::new();
    for layout in layouts {
        let profile_root = home.join(layout.profile_relative);
        if !profile_root.is_dir() {
            continue;
        }
        let mut exe_paths = Vec::new();
        for candidate in layout.executable_candidates {
            if let Some(path) = canonical_executable(Path::new(candidate)) {
                if !exe_paths.contains(&path) {
                    exe_paths.push(path);
                }
            }
        }
        if !exe_paths.is_empty() {
            browsers.push(BrowserSuggestion {
                id: layout.id.to_owned(),
                family: layout.family,
                profile_root,
                exe_paths,
            });
        }
    }
    let unsupported_sandboxed = [
        (
            "snap-firefox",
            home.join("snap/firefox/common/.mozilla/firefox"),
        ),
        (
            "flatpak-firefox",
            home.join(".var/app/org.mozilla.firefox/.mozilla/firefox"),
        ),
        (
            "flatpak-chromium",
            home.join(".var/app/org.chromium.Chromium/config/chromium"),
        ),
    ]
    .into_iter()
    .filter(|(_, path)| path.is_dir())
    .map(|(kind, profile_root)| UnsupportedSandboxedBrowser {
        kind: kind.to_owned(),
        profile_root,
        reason:
            "sandbox namespace and filesystem-mark visibility are not security-accepted in Linux V1"
                .to_owned(),
    })
    .collect();
    BrowserDiscovery {
        browsers,
        unsupported_sandboxed,
    }
}

fn canonical_executable(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return None;
    }
    std::fs::canonicalize(path).ok()
}

pub fn family_name(family: BrowserFamily) -> &'static str {
    match family {
        BrowserFamily::Firefox => "Firefox",
        BrowserFamily::Zen => "Zen",
        BrowserFamily::Chromium => "Chromium",
    }
}

pub fn browser_id(id: &str) -> BrowserId {
    BrowserId(id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> EnforcementConfig {
        EnforcementConfig {
            enforcement_mode: EnforcementMode::Conservative,
            browsers: Vec::new(),
            enrolled_exes: vec![PathBuf::from("/synthetic/exe")],
            ssh_keys: Vec::new(),
        }
    }

    #[test]
    fn ssh_key_only_configuration_is_valid() {
        assert!(config().validate().is_ok());
    }

    #[test]
    fn legacy_behavior_window_is_ignored() {
        let config: EnforcementConfig = serde_json::from_str(
            r#"{"browsers":[],"enrolled_exes":["/synthetic/exe"],"ssh_keys":[],"ssh_behavior_window_secs":10}"#,
        )
        .unwrap();
        assert_eq!(config.enrolled_exes, vec![PathBuf::from("/synthetic/exe")]);
    }
}
