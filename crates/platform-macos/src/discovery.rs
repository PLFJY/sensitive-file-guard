use std::path::{Path, PathBuf};
use std::sync::Arc;

use guard_core::resource::{BrowserFamily, BrowserId};
use guard_platform::config::{BrowserDiscovery, BrowserSuggestion, UnsupportedSandboxedBrowser};
use serde::{Deserialize, Serialize};

use crate::browser_trust::{
    enroll_custom_executable, BrowserExecutableRole, MacBrowserEnrollment, MacExecutableEnrollment,
};
use crate::code_signature::{CodeSignatureInspector, SignatureInspection};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserExecutableReview {
    pub role: BrowserExecutableRole,
    pub path: PathBuf,
    pub team_id: String,
    pub signing_id: String,
    pub cdhash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacBrowserReview {
    pub browser_id: BrowserId,
    pub family: BrowserFamily,
    pub app_bundle: PathBuf,
    pub profile_root: PathBuf,
    pub owner_uid: u32,
    pub executables: Vec<BrowserExecutableReview>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacBrowserDiscoveryResult {
    pub enrollments: Vec<MacBrowserEnrollment>,
    pub review: Vec<MacBrowserReview>,
    pub portable: BrowserDiscovery,
}

pub struct MacBrowserDiscovery {
    application_roots: Vec<PathBuf>,
    signatures: Arc<dyn CodeSignatureInspector>,
}

impl MacBrowserDiscovery {
    pub fn new(
        application_roots: Vec<PathBuf>,
        signatures: Arc<dyn CodeSignatureInspector>,
    ) -> Self {
        Self {
            application_roots,
            signatures,
        }
    }

    pub fn system(signatures: Arc<dyn CodeSignatureInspector>) -> Self {
        Self::new(vec![PathBuf::from("/Applications")], signatures)
    }

    pub fn discover_verified(&self, home: &Path) -> MacBrowserDiscoveryResult {
        use std::os::unix::fs::MetadataExt;

        let owner_uid = std::fs::metadata(home)
            .map(|metadata| metadata.uid())
            .unwrap_or(u32::MAX);
        let mut enrollments = Vec::new();
        let mut review = Vec::new();
        let mut suggestions = Vec::new();
        let mut unsupported = Vec::new();

        for definition in BROWSERS {
            let profile_root = home.join(definition.profile_relative);
            if !profile_root.is_dir() {
                continue;
            }
            let profile_root = match std::fs::canonicalize(&profile_root) {
                Ok(profile_root) => profile_root,
                Err(error) => {
                    unsupported.push(unsupported_browser(
                        definition,
                        profile_root,
                        &format!("profile root cannot be canonicalized: {error}"),
                    ));
                    continue;
                }
            };
            let Some(app) = self
                .application_roots
                .iter()
                .map(|root| root.join(definition.app_name))
                .find(|path| path.is_dir())
            else {
                unsupported.push(unsupported_browser(
                    definition,
                    profile_root,
                    "profile root exists but the verified native app is not installed",
                ));
                continue;
            };
            match self.enroll_known(definition, &app, &profile_root, owner_uid) {
                Ok((enrollment, browser_review)) => {
                    suggestions.push(BrowserSuggestion {
                        id: definition.id.to_owned(),
                        family: definition.family,
                        profile_root: enrollment.profile_root.clone(),
                        exe_paths: enrollment
                            .executables
                            .iter()
                            .map(|executable| executable.path().to_path_buf())
                            .collect(),
                    });
                    enrollments.push(enrollment);
                    review.push(browser_review);
                }
                Err(error) => unsupported.push(unsupported_browser(
                    definition,
                    profile_root,
                    &format!("native app needs custom enrollment: {error}"),
                )),
            }
        }

        detect_unsupported_safari_at(home, &mut unsupported);

        MacBrowserDiscoveryResult {
            enrollments,
            review,
            portable: BrowserDiscovery {
                browsers: suggestions,
                unsupported_sandboxed: unsupported,
            },
        }
    }

    pub fn enroll_custom(
        &self,
        id: BrowserId,
        family: BrowserFamily,
        profile_root: &Path,
        executable: &Path,
        owner_uid: u32,
    ) -> anyhow::Result<MacBrowserEnrollment> {
        let profile_root = std::fs::canonicalize(profile_root)?;
        let executable = std::fs::canonicalize(executable)?;
        let signature = self.signatures.inspect(&executable).ok();
        if let Some(signature) = signature.filter(|signature| {
            signature.valid && signature.team_id.is_some() && signature.signing_id.is_some()
        }) {
            if let Some(app_bundle) = containing_app_bundle(&executable) {
                return Ok(MacBrowserEnrollment {
                    browser_id: id,
                    family,
                    profile_root,
                    owner_uid,
                    app_bundle: Some(app_bundle),
                    executables: vec![signed_enrollment(
                        BrowserExecutableRole::Main,
                        executable,
                        &signature,
                    )?],
                });
            }
        }
        Ok(MacBrowserEnrollment {
            browser_id: id,
            family,
            profile_root,
            owner_uid,
            app_bundle: None,
            executables: vec![enroll_custom_executable(&executable)?],
        })
    }

    fn enroll_known(
        &self,
        definition: &BrowserDefinition,
        app: &Path,
        profile_root: &Path,
        owner_uid: u32,
    ) -> anyhow::Result<(MacBrowserEnrollment, MacBrowserReview)> {
        let app = std::fs::canonicalize(app)?;
        let mut executables = Vec::new();
        let mut executable_review = Vec::new();
        for executable in std::iter::once(&definition.main).chain(definition.helpers) {
            let path = app.join(executable.relative_path);
            if !path.is_file() {
                if executable.role == BrowserExecutableRole::Main {
                    anyhow::bail!("main executable is missing: {}", path.display());
                }
                continue;
            }
            let path = std::fs::canonicalize(path)?;
            anyhow::ensure!(
                path.starts_with(&app),
                "nested helper escaped its app bundle"
            );
            let signature = self.signatures.inspect(&path)?;
            anyhow::ensure!(
                signature.valid,
                "signature validation failed for {}",
                path.display()
            );
            anyhow::ensure!(
                signature.team_id.as_deref() == Some(definition.team_id),
                "unexpected Team ID for {}",
                path.display()
            );
            anyhow::ensure!(
                executable
                    .signing_ids
                    .contains(&signature.signing_id.as_deref().unwrap_or("")),
                "unexpected signing ID for {}",
                path.display()
            );
            executables.push(signed_enrollment(
                executable.role,
                path.clone(),
                &signature,
            )?);
            executable_review.push(BrowserExecutableReview {
                role: executable.role,
                path,
                team_id: signature.team_id.unwrap_or_default(),
                signing_id: signature.signing_id.unwrap_or_default(),
                cdhash_hex: hex(&signature.cdhash),
            });
        }
        anyhow::ensure!(
            !executables.is_empty(),
            "no trusted browser executable found"
        );
        let enrollment = MacBrowserEnrollment {
            browser_id: BrowserId(definition.id.to_owned()),
            family: definition.family,
            profile_root: profile_root.to_path_buf(),
            owner_uid,
            app_bundle: Some(app.clone()),
            executables,
        };
        let review = MacBrowserReview {
            browser_id: enrollment.browser_id.clone(),
            family: enrollment.family,
            app_bundle: app,
            profile_root: profile_root.to_path_buf(),
            owner_uid,
            executables: executable_review,
        };
        Ok((enrollment, review))
    }
}

impl guard_platform::BrowserDiscovery for MacBrowserDiscovery {
    fn discover(&self, home: &Path) -> BrowserDiscovery {
        self.discover_verified(home).portable
    }
}

fn signed_enrollment(
    role: BrowserExecutableRole,
    path: PathBuf,
    signature: &SignatureInspection,
) -> anyhow::Result<MacExecutableEnrollment> {
    Ok(MacExecutableEnrollment::Signed {
        role,
        bundle_suffix: (role == BrowserExecutableRole::Helper)
            .then(|| helper_bundle_suffix(&path))
            .flatten(),
        path,
        team_id: signature
            .team_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("signed executable has no Team ID"))?,
        signing_id: signature
            .signing_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("signed executable has no signing ID"))?,
    })
}

fn helper_bundle_suffix(path: &Path) -> Option<PathBuf> {
    let components = path.components().collect::<Vec<_>>();
    let helpers = components
        .iter()
        .position(|component| component.as_os_str() == "Helpers")?;
    let mut suffix = PathBuf::new();
    for component in &components[helpers + 1..] {
        suffix.push(component.as_os_str());
    }
    (!suffix.as_os_str().is_empty()).then_some(suffix)
}

fn containing_app_bundle(executable: &Path) -> Option<PathBuf> {
    executable.ancestors().find_map(|ancestor| {
        ancestor
            .extension()
            .is_some_and(|extension| extension == "app")
            .then(|| ancestor.to_path_buf())
    })
}

fn unsupported_browser(
    definition: &BrowserDefinition,
    profile_root: PathBuf,
    reason: &str,
) -> UnsupportedSandboxedBrowser {
    UnsupportedSandboxedBrowser {
        kind: definition.id.to_owned(),
        profile_root,
        reason: reason.to_owned(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Copy)]
struct BrowserExecutableDefinition {
    role: BrowserExecutableRole,
    relative_path: &'static str,
    signing_ids: &'static [&'static str],
}

struct BrowserDefinition {
    id: &'static str,
    family: BrowserFamily,
    app_name: &'static str,
    profile_relative: &'static str,
    team_id: &'static str,
    main: BrowserExecutableDefinition,
    helpers: &'static [BrowserExecutableDefinition],
}

const CHROME_HELPERS: &[BrowserExecutableDefinition] = &[
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper",
        signing_ids: &["com.google.Chrome.helper"],
    },
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Helpers/Google Chrome Helper (GPU).app/Contents/MacOS/Google Chrome Helper (GPU)",
        signing_ids: &["com.google.Chrome.helper"],
    },
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/Frameworks/Google Chrome Framework.framework/Versions/Current/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer)",
        signing_ids: &["com.google.Chrome.helper.renderer"],
    },
];

const CHROMIUM_HELPERS: &[BrowserExecutableDefinition] = &[
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/Frameworks/Chromium Framework.framework/Versions/Current/Helpers/Chromium Helper.app/Contents/MacOS/Chromium Helper",
        signing_ids: &["org.chromium.Chromium.helper"],
    },
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/Frameworks/Chromium Framework.framework/Versions/Current/Helpers/Chromium Helper (Renderer).app/Contents/MacOS/Chromium Helper (Renderer)",
        signing_ids: &["org.chromium.Chromium.helper.renderer"],
    },
];

const EDGE_HELPERS: &[BrowserExecutableDefinition] = &[
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/Frameworks/Microsoft Edge Framework.framework/Versions/Current/Helpers/Microsoft Edge Helper.app/Contents/MacOS/Microsoft Edge Helper",
        signing_ids: &["com.microsoft.edgemac.helper"],
    },
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/Frameworks/Microsoft Edge Framework.framework/Versions/Current/Helpers/Microsoft Edge Helper (GPU).app/Contents/MacOS/Microsoft Edge Helper (GPU)",
        signing_ids: &["com.microsoft.edgemac.helper"],
    },
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/Frameworks/Microsoft Edge Framework.framework/Versions/Current/Helpers/Microsoft Edge Helper (Renderer).app/Contents/MacOS/Microsoft Edge Helper (Renderer)",
        signing_ids: &["com.microsoft.edgemac.helper.renderer"],
    },
];

const FIREFOX_HELPERS: &[BrowserExecutableDefinition] = &[
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/MacOS/plugin-container.app/Contents/MacOS/plugin-container",
        signing_ids: &["org.mozilla.plugincontainer"],
    },
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path: "Contents/MacOS/gpu-helper.app/Contents/MacOS/Firefox GPU Helper",
        signing_ids: &["org.mozilla.firefox-gpu-helper"],
    },
    BrowserExecutableDefinition {
        role: BrowserExecutableRole::Helper,
        relative_path:
            "Contents/MacOS/media-plugin-helper.app/Contents/MacOS/Firefox Media Plugin Helper",
        signing_ids: &["org.mozilla.firefox-media-plugin-helper"],
    },
];

const BROWSERS: &[BrowserDefinition] = &[
    BrowserDefinition {
        id: "chrome",
        family: BrowserFamily::Chromium,
        app_name: "Google Chrome.app",
        profile_relative: "Library/Application Support/Google/Chrome",
        team_id: "EQHXZ8M8AV",
        main: BrowserExecutableDefinition {
            role: BrowserExecutableRole::Main,
            relative_path: "Contents/MacOS/Google Chrome",
            signing_ids: &["com.google.Chrome"],
        },
        helpers: CHROME_HELPERS,
    },
    BrowserDefinition {
        id: "chromium",
        family: BrowserFamily::Chromium,
        app_name: "Chromium.app",
        profile_relative: "Library/Application Support/Chromium",
        team_id: "EQHXZ8M8AV",
        main: BrowserExecutableDefinition {
            role: BrowserExecutableRole::Main,
            relative_path: "Contents/MacOS/Chromium",
            signing_ids: &["org.chromium.Chromium"],
        },
        helpers: CHROMIUM_HELPERS,
    },
    BrowserDefinition {
        id: "edge",
        family: BrowserFamily::Chromium,
        app_name: "Microsoft Edge.app",
        profile_relative: "Library/Application Support/Microsoft Edge",
        team_id: "UBF8T346G9",
        main: BrowserExecutableDefinition {
            role: BrowserExecutableRole::Main,
            relative_path: "Contents/MacOS/Microsoft Edge",
            signing_ids: &["com.microsoft.edgemac"],
        },
        helpers: EDGE_HELPERS,
    },
    BrowserDefinition {
        id: "firefox",
        family: BrowserFamily::Firefox,
        app_name: "Firefox.app",
        profile_relative: "Library/Application Support/Firefox/Profiles",
        team_id: "43AQ936H96",
        main: BrowserExecutableDefinition {
            role: BrowserExecutableRole::Main,
            relative_path: "Contents/MacOS/firefox",
            signing_ids: &["org.mozilla.firefox"],
        },
        helpers: FIREFOX_HELPERS,
    },
];

fn detect_unsupported_safari_at(home: &Path, unsupported: &mut Vec<UnsupportedSandboxedBrowser>) {
    let profile_root = home.join("Library/Safari");
    if !profile_root.is_dir() {
        return;
    }
    let profile_root = std::fs::canonicalize(&profile_root).unwrap_or(profile_root);
    let safari_app_exists = [
        Path::new("/System/Applications/Safari.app"),
        Path::new("/Applications/Safari.app"),
    ]
    .iter()
    .any(|path| path.is_dir());
    unsupported.push(UnsupportedSandboxedBrowser {
        kind: "safari".to_owned(),
        profile_root,
        reason: if safari_app_exists {
            "Safari is detected but not protected: Guard does not yet have a Safari resource classifier or trusted WebKit process enrollment."
        } else {
            "Safari data is detected but the Safari app was not found in a standard location; Guard also does not yet have a Safari resource classifier or trusted WebKit process enrollment."
        }
        .to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeSignatures {
        values: Mutex<HashMap<PathBuf, SignatureInspection>>,
    }

    impl CodeSignatureInspector for FakeSignatures {
        fn inspect(&self, executable: &Path) -> anyhow::Result<SignatureInspection> {
            self.values
                .lock()
                .unwrap()
                .get(executable)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unsigned fixture"))
        }
    }

    fn create_known(
        home: &Path,
        applications: &Path,
        definition: &BrowserDefinition,
        signatures: &FakeSignatures,
    ) {
        let profile = home.join(definition.profile_relative);
        std::fs::create_dir_all(profile).unwrap();
        let executable = applications
            .join(definition.app_name)
            .join(definition.main.relative_path);
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        std::fs::write(&executable, b"synthetic browser executable").unwrap();
        let executable = std::fs::canonicalize(executable).unwrap();
        signatures.values.lock().unwrap().insert(
            executable,
            SignatureInspection {
                valid: true,
                team_id: Some(definition.team_id.to_owned()),
                signing_id: Some(definition.main.signing_ids[0].to_owned()),
                leaf_certificate_sha1: None,
                cdhash: vec![1; 20],
                diagnostic: None,
            },
        );
    }

    #[test]
    fn discovers_verified_chrome_chromium_edge_and_firefox_synthetic_layouts() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let applications = temp.path().join("Applications");
        std::fs::create_dir_all(&home).unwrap();
        let signatures = Arc::new(FakeSignatures::default());
        for definition in BROWSERS {
            create_known(&home, &applications, definition, &signatures);
        }
        let discovery = MacBrowserDiscovery::new(vec![applications], signatures);
        let result = discovery.discover_verified(&home);
        let ids = result
            .review
            .iter()
            .map(|browser| browser.browser_id.0.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec!["chrome", "chromium", "edge", "firefox"],
            "unsupported: {:?}",
            result.portable.unsupported_sandboxed
        );
        assert!(result.portable.unsupported_sandboxed.is_empty());
    }

    #[test]
    fn safari_is_reported_as_detected_but_not_enrolled() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let safari = home.join("Library/Safari");
        std::fs::create_dir_all(&safari).unwrap();

        // Safari discovery deliberately never creates an enrollment until a
        // dedicated classifier exists.
        let mut unsupported = Vec::new();
        detect_unsupported_safari_at(&home, &mut unsupported);
        assert_eq!(unsupported.len(), 1);
        assert_eq!(unsupported[0].kind, "safari");
        assert!(unsupported[0].reason.contains("not protected"));
    }

    #[test]
    fn no_profile_root_means_no_automatic_enrollment() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let applications = temp.path().join("Applications");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(applications.join("Google Chrome.app")).unwrap();
        let discovery =
            MacBrowserDiscovery::new(vec![applications], Arc::new(FakeSignatures::default()));
        let result = discovery.discover_verified(&home);
        assert!(result.enrollments.is_empty());
        assert!(result.portable.unsupported_sandboxed.is_empty());
    }

    #[test]
    fn wrong_signer_is_custom_needed_not_automatically_trusted() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let applications = temp.path().join("Applications");
        std::fs::create_dir_all(&home).unwrap();
        let signatures = Arc::new(FakeSignatures::default());
        create_known(&home, &applications, &BROWSERS[0], &signatures);
        let main = applications
            .join(BROWSERS[0].app_name)
            .join(BROWSERS[0].main.relative_path);
        let main = std::fs::canonicalize(main).unwrap();
        signatures
            .values
            .lock()
            .unwrap()
            .get_mut(&main)
            .unwrap()
            .team_id = Some("WRONG".to_owned());
        let discovery = MacBrowserDiscovery::new(vec![applications], signatures);
        let result = discovery.discover_verified(&home);
        assert!(result.enrollments.is_empty());
        assert_eq!(result.portable.unsupported_sandboxed.len(), 1);
        assert!(result.portable.unsupported_sandboxed[0]
            .reason
            .contains("custom enrollment"));
    }

    #[test]
    fn custom_unsigned_executable_is_hash_enrolled() {
        let temp = tempfile::tempdir().unwrap();
        let profile = temp.path().join("custom-profile");
        let executable = temp.path().join("custom-browser");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::write(&executable, b"synthetic custom browser").unwrap();
        let discovery = MacBrowserDiscovery::new(vec![], Arc::new(FakeSignatures::default()));
        let enrollment = discovery
            .enroll_custom(
                BrowserId("custom".to_owned()),
                BrowserFamily::Chromium,
                &profile,
                &executable,
                501,
            )
            .unwrap();
        assert!(matches!(
            enrollment.executables.as_slice(),
            [MacExecutableEnrollment::ExplicitHash { .. }]
        ));
    }
}
