use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInspection {
    pub valid: bool,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub cdhash: Vec<u8>,
    pub diagnostic: Option<String>,
}

pub trait CodeSignatureInspector: Send + Sync {
    fn inspect(&self, executable: &Path) -> anyhow::Result<SignatureInspection>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NativeCodeSignatureInspector;

#[cfg(target_os = "macos")]
impl CodeSignatureInspector for NativeCodeSignatureInspector {
    fn inspect(&self, executable: &Path) -> anyhow::Result<SignatureInspection> {
        use std::os::unix::ffi::OsStrExt;

        let canonical = std::fs::canonicalize(executable)?;
        let path = std::ffi::CString::new(canonical.as_os_str().as_bytes())?;
        let mut raw = RawSignatureInfo {
            valid: false,
            team_id: [0; 128],
            signing_id: [0; 256],
            cdhash: [0; 20],
            cdhash_len: 0,
        };
        let mut error = [0_i8; 512];
        // SAFETY: path and both output buffers remain live and writable for
        // the complete synchronous Security.framework inspection.
        let result = unsafe {
            guard_code_signature_inspect(path.as_ptr(), &mut raw, error.as_mut_ptr(), error.len())
        };
        anyhow::ensure!(
            result == 0,
            "{}",
            c_string(&error).unwrap_or_else(|| "code signature inspection failed".to_owned())
        );
        anyhow::ensure!(
            raw.cdhash_len <= raw.cdhash.len(),
            "invalid code-directory hash length"
        );
        Ok(SignatureInspection {
            valid: raw.valid,
            team_id: c_string(&raw.team_id),
            signing_id: c_string(&raw.signing_id),
            cdhash: raw.cdhash[..raw.cdhash_len].to_vec(),
            diagnostic: c_string(&error),
        })
    }
}

#[cfg(not(target_os = "macos"))]
impl CodeSignatureInspector for NativeCodeSignatureInspector {
    fn inspect(&self, _executable: &Path) -> anyhow::Result<SignatureInspection> {
        anyhow::bail!("Security.framework code signature inspection is available only on macOS")
    }
}

#[cfg(target_os = "macos")]
fn c_string(buffer: &[std::ffi::c_char]) -> Option<String> {
    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    if length == 0 {
        return None;
    }
    let bytes = buffer[..length]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8(bytes).ok()
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct RawSignatureInfo {
    valid: bool,
    team_id: [std::ffi::c_char; 128],
    signing_id: [std::ffi::c_char; 256],
    cdhash: [u8; 20],
    cdhash_len: usize,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn guard_code_signature_inspect(
        path: *const std::ffi::c_char,
        info: *mut RawSignatureInfo,
        error: *mut std::ffi::c_char,
        error_len: usize,
    ) -> i32;
}
