//! Shared public Linux configuration and native browser suggestions.
//!
//! This module intentionally contains data validation and discovery only.  It
//! does not decide whether a process may open a resource; that remains in the
//! daemon enforcement engine.

use std::path::{Path, PathBuf};

use guard_core::resource::{BrowserFamily, BrowserId};
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
    /// Validate the public contract before a privileged write or daemon start.
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

pub fn discover_native_browsers(home: &Path) -> BrowserDiscovery {
    discover_native_browsers_with_layouts(home, NATIVE_BROWSER_LAYOUTS)
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
