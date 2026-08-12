use std::ffi::CString;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Unknown,
    Submitted,
    UserApprovalRequired,
    Active,
    RestartRequired,
    Deactivated,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleStatus {
    pub state: LifecycleState,
    pub diagnostic: String,
}

pub struct SystemExtensionController {
    identifier: CString,
}

impl SystemExtensionController {
    pub fn new(identifier: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            crate::bundle::valid_bundle_identifier(identifier),
            "invalid system extension bundle identifier"
        );
        Ok(Self {
            identifier: CString::new(identifier)?,
        })
    }

    #[cfg(target_os = "macos")]
    pub fn activate(&self) -> anyhow::Result<()> {
        self.submit(guard_system_extension_activate)
    }
    #[cfg(not(target_os = "macos"))]
    pub fn activate(&self) -> anyhow::Result<()> {
        anyhow::bail!("SystemExtensions is available only on macOS")
    }

    #[cfg(target_os = "macos")]
    pub fn deactivate(&self) -> anyhow::Result<()> {
        self.submit(guard_system_extension_deactivate)
    }
    #[cfg(not(target_os = "macos"))]
    pub fn deactivate(&self) -> anyhow::Result<()> {
        anyhow::bail!("SystemExtensions is available only on macOS")
    }

    #[cfg(target_os = "macos")]
    pub fn refresh(&self) -> anyhow::Result<()> {
        self.submit(guard_system_extension_refresh)
    }
    #[cfg(not(target_os = "macos"))]
    pub fn refresh(&self) -> anyhow::Result<()> {
        anyhow::bail!("SystemExtensions is available only on macOS")
    }

    #[cfg(target_os = "macos")]
    fn submit(
        &self,
        function: unsafe extern "C" fn(
            *const std::ffi::c_char,
            *mut std::ffi::c_char,
            usize,
        ) -> i32,
    ) -> anyhow::Result<()> {
        let mut error = vec![0_i8; 1024];
        // SAFETY: identifier is a live NUL-terminated CString; `error` is a
        // writable buffer of the supplied length for the duration of the call.
        let result = unsafe { function(self.identifier.as_ptr(), error.as_mut_ptr(), error.len()) };
        if result == 0 {
            return Ok(());
        }
        anyhow::bail!(
            buffer_string(&error).unwrap_or_else(|| "SystemExtensions request failed".to_owned())
        )
    }

    #[cfg(target_os = "macos")]
    pub fn status(&self) -> anyhow::Result<LifecycleStatus> {
        let mut diagnostic = vec![0_i8; 1024];
        // SAFETY: identifier and output buffer satisfy the bridge contract and
        // remain live for the complete synchronous status-copy call.
        let raw = unsafe {
            guard_system_extension_status(
                self.identifier.as_ptr(),
                diagnostic.as_mut_ptr(),
                diagnostic.len(),
            )
        };
        let state = match raw {
            0 => LifecycleState::Unknown,
            1 => LifecycleState::Submitted,
            2 => LifecycleState::UserApprovalRequired,
            3 => LifecycleState::Active,
            4 => LifecycleState::RestartRequired,
            5 => LifecycleState::Deactivated,
            6 => LifecycleState::Failed,
            _ => anyhow::bail!("SystemExtensions bridge returned invalid state {raw}"),
        };
        Ok(LifecycleStatus {
            state,
            diagnostic: buffer_string(&diagnostic).unwrap_or_default(),
        })
    }

    #[cfg(not(target_os = "macos"))]
    pub fn status(&self) -> anyhow::Result<LifecycleStatus> {
        anyhow::bail!("SystemExtensions is available only on macOS")
    }
}

#[cfg(target_os = "macos")]
pub fn host_install_entitlement_present() -> anyhow::Result<bool> {
    entitlement_present("com.apple.developer.system-extension.install")
}

#[cfg(not(target_os = "macos"))]
pub fn host_install_entitlement_present() -> anyhow::Result<bool> {
    anyhow::bail!("system-extension entitlement inspection is available only on macOS")
}

#[cfg(target_os = "macos")]
pub fn endpoint_security_entitlement_present() -> anyhow::Result<bool> {
    entitlement_present("com.apple.developer.endpoint-security.client")
}

#[cfg(target_os = "macos")]
pub fn bundled_endpoint_security_entitlement_present(
    app: &Path,
    extension_bundle_id: &str,
) -> anyhow::Result<bool> {
    let extension =
        crate::bundle::DevelopmentBundleLayout::new(app, extension_bundle_id)?.extension();
    path_entitlement_present(&extension, "com.apple.developer.endpoint-security.client")
}

#[cfg(not(target_os = "macos"))]
pub fn bundled_endpoint_security_entitlement_present(
    _app: &Path,
    _extension_bundle_id: &str,
) -> anyhow::Result<bool> {
    anyhow::bail!("bundle entitlement inspection is available only on macOS")
}

#[cfg(target_os = "macos")]
fn entitlement_present(entitlement: &str) -> anyhow::Result<bool> {
    let entitlement = CString::new(entitlement)?;
    let mut error = vec![0_i8; 1024];
    // SAFETY: the bridge receives only a writable diagnostic buffer and does
    // not retain it after returning.
    let result =
        unsafe { guard_has_entitlement(entitlement.as_ptr(), error.as_mut_ptr(), error.len()) };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => anyhow::bail!(
            buffer_string(&error).unwrap_or_else(|| "entitlement inspection failed".to_owned())
        ),
    }
}

#[cfg(target_os = "macos")]
fn path_entitlement_present(path: &Path, entitlement: &str) -> anyhow::Result<bool> {
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes())?;
    let entitlement = CString::new(entitlement)?;
    let mut error = vec![0_i8; 1024];
    // SAFETY: both input strings are live and NUL-terminated, and the writable
    // diagnostic buffer remains valid for the synchronous bridge call.
    let result = unsafe {
        guard_path_has_entitlement(
            path.as_ptr(),
            entitlement.as_ptr(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => {
            anyhow::bail!(buffer_string(&error)
                .unwrap_or_else(|| "bundle entitlement inspection failed".into()))
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub fn endpoint_security_entitlement_present() -> anyhow::Result<bool> {
    anyhow::bail!("Endpoint Security entitlement inspection is available only on macOS")
}

#[cfg(target_os = "macos")]
fn buffer_string(buffer: &[std::ffi::c_char]) -> Option<String> {
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    if end == 0 {
        return None;
    }
    let bytes = buffer[..end]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(target_os = "macos")]
extern "C" {
    fn guard_system_extension_activate(
        identifier: *const std::ffi::c_char,
        error: *mut std::ffi::c_char,
        error_len: usize,
    ) -> i32;
    fn guard_system_extension_deactivate(
        identifier: *const std::ffi::c_char,
        error: *mut std::ffi::c_char,
        error_len: usize,
    ) -> i32;
    fn guard_system_extension_refresh(
        identifier: *const std::ffi::c_char,
        error: *mut std::ffi::c_char,
        error_len: usize,
    ) -> i32;
    fn guard_system_extension_status(
        identifier: *const std::ffi::c_char,
        diagnostic: *mut std::ffi::c_char,
        diagnostic_len: usize,
    ) -> i32;
    fn guard_has_entitlement(
        entitlement: *const std::ffi::c_char,
        error: *mut std::ffi::c_char,
        error_len: usize,
    ) -> i32;
    fn guard_path_has_entitlement(
        path: *const std::ffi::c_char,
        entitlement: *const std::ffi::c_char,
        error: *mut std::ffi::c_char,
        error_len: usize,
    ) -> i32;
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn rejects_missing_nested_extension_without_activating_it() {
        let temporary = tempfile::tempdir().unwrap();
        let app = temporary.path().join("Guard Review With Spaces.app");
        let error =
            bundled_endpoint_security_entitlement_present(&app, crate::DEFAULT_EXTENSION_BUNDLE_ID)
                .unwrap_err();
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn reads_entitlement_from_signed_nested_extension_at_path_with_spaces() {
        let temporary = tempfile::tempdir().unwrap();
        let app = temporary.path().join("Guard Review With Spaces.app");
        let layout =
            crate::bundle::DevelopmentBundleLayout::new(&app, crate::DEFAULT_EXTENSION_BUNDLE_ID)
                .unwrap();
        std::fs::create_dir_all(layout.extension().join("Contents/MacOS")).unwrap();
        std::fs::copy("/usr/bin/true", layout.extension_executable()).unwrap();
        std::fs::write(
            layout.extension_info_plist(),
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>guard-es</string>
<key>CFBundleIdentifier</key><string>{}</string>
<key>CFBundlePackageType</key><string>SYSX</string>
</dict></plist>"#,
                crate::DEFAULT_EXTENSION_BUNDLE_ID
            ),
        )
        .unwrap();
        let entitlements = temporary.path().join("Guard ES Entitlements.plist");
        std::fs::write(
            &entitlements,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>com.apple.developer.endpoint-security.client</key><true/>
</dict></plist>"#,
        )
        .unwrap();
        let output = Command::new("codesign")
            .args(["--force", "--sign", "-", "--entitlements"])
            .arg(&entitlements)
            .arg(layout.extension())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(bundled_endpoint_security_entitlement_present(
            &app,
            crate::DEFAULT_EXTENSION_BUNDLE_ID
        )
        .unwrap());
    }
}
