use std::path::{Path, PathBuf};

/// Runtime exception entitlements of a signed executable (MPS7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RuntimeEntitlementFacts {
    /// Whether the signature carried an entitlements dictionary at all.
    /// Absent => the runtime posture cannot be verified.
    pub has_entitlements: bool,
    pub get_task_allow: bool,
    pub allow_dyld_environment_variables: bool,
    pub disable_library_validation: bool,
    pub disable_executable_page_protection: bool,
    pub allow_unsigned_executable_memory: bool,
    pub allow_jit: bool,
}

impl RuntimeEntitlementFacts {
    /// Security-relevant exceptions that materially weaken Process Shield
    /// (or leak task capabilities). allow_jit is deliberately excluded: it is
    /// the legitimate browser JIT entitlement, narrower than unsigned
    /// executable memory, and must not be treated as a generic failure.
    pub fn has_reduced_runtime_exceptions(&self) -> bool {
        self.get_task_allow
            || self.allow_dyld_environment_variables
            || self.disable_library_validation
            || self.disable_executable_page_protection
            || self.allow_unsigned_executable_memory
    }

    pub fn present_reasons(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self.get_task_allow {
            reasons.push("get-task-allow");
        }
        if self.allow_dyld_environment_variables {
            reasons.push("allow-dyld-environment-variables");
        }
        if self.disable_library_validation {
            reasons.push("disable-library-validation");
        }
        if self.disable_executable_page_protection {
            reasons.push("disable-executable-page-protection");
        }
        if self.allow_unsigned_executable_memory {
            reasons.push("allow-unsigned-executable-memory");
        }
        if self.allow_jit {
            reasons.push("allow-jit (narrow/legitimate)");
        }
        reasons
    }
}

/// Runtime posture of an enrolled executable. Truthful and additive: it never
/// changes browser identity semantics by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimePosture {
    /// No security-relevant runtime exceptions; entitlements verified.
    Strong,
    /// One or more documented runtime exceptions are present (get-task-allow,
    /// DYLD environment, disabled library validation, unsigned executable
    /// memory, disabled executable-page protection).
    Reduced,
    /// Entitlements could not be verified (unsigned, ad-hoc, or inspection
    /// failure). Reported as unverifiable, never silently trusted.
    Unverifiable,
}

impl RuntimePosture {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Strong => "strong",
            Self::Reduced => "reduced",
            Self::Unverifiable => "unverifiable",
        }
    }
}

/// Pure mapping of entitlement facts to posture — unit-tested without a real
/// signed binary.
pub fn posture_from_facts(facts: &RuntimeEntitlementFacts) -> RuntimePosture {
    if !facts.has_entitlements {
        return RuntimePosture::Unverifiable;
    }
    if facts.has_reduced_runtime_exceptions() {
        return RuntimePosture::Reduced;
    }
    RuntimePosture::Strong
}

/// One executable's runtime posture report (metadata only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePostureReport {
    pub executable: PathBuf,
    pub posture: RuntimePosture,
    /// Present security-relevant exception names (plus allow-jit noted
    /// separately as narrow/legitimate).
    pub reasons: Vec<String>,
}

pub trait CodeSignatureInspector: Send + Sync {
    fn inspect(&self, executable: &Path) -> anyhow::Result<SignatureInspection>;
}

pub trait RuntimePostureInspector: Send + Sync {
    fn inspect_runtime(&self, executable: &Path) -> anyhow::Result<RuntimeEntitlementFacts>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NativeCodeSignatureInspector;

#[cfg(target_os = "macos")]
impl RuntimePostureInspector for NativeCodeSignatureInspector {
    fn inspect_runtime(&self, executable: &Path) -> anyhow::Result<RuntimeEntitlementFacts> {
        use std::os::unix::ffi::OsStrExt;

        let canonical = std::fs::canonicalize(executable)?;
        let path = std::ffi::CString::new(canonical.as_os_str().as_bytes())?;
        let mut raw = RawRuntimeInfo {
            has_entitlements: false,
            get_task_allow: false,
            allow_dyld_environment_variables: false,
            disable_library_validation: false,
            disable_executable_page_protection: false,
            allow_unsigned_executable_memory: false,
            allow_jit: false,
        };
        let mut error = [0_i8; 512];
        // SAFETY: path and the output buffer remain live and writable for the
        // complete synchronous Security.framework inspection.
        let result = unsafe {
            guard_code_signature_runtime_inspect(
                path.as_ptr(),
                &mut raw,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        anyhow::ensure!(
            result == 0,
            "{}",
            c_string(&error).unwrap_or_else(|| "runtime signature inspection failed".to_owned())
        );
        Ok(RuntimeEntitlementFacts {
            has_entitlements: raw.has_entitlements,
            get_task_allow: raw.get_task_allow,
            allow_dyld_environment_variables: raw.allow_dyld_environment_variables,
            disable_library_validation: raw.disable_library_validation,
            disable_executable_page_protection: raw.disable_executable_page_protection,
            allow_unsigned_executable_memory: raw.allow_unsigned_executable_memory,
            allow_jit: raw.allow_jit,
        })
    }
}

#[cfg(not(target_os = "macos"))]
impl RuntimePostureInspector for NativeCodeSignatureInspector {
    fn inspect_runtime(&self, _executable: &Path) -> anyhow::Result<RuntimeEntitlementFacts> {
        anyhow::bail!("Security.framework runtime inspection is available only on macOS")
    }
}

/// Convenience: runtime posture of one executable.
pub fn runtime_posture_of(executable: &Path) -> RuntimePostureReport {
    let facts = NativeCodeSignatureInspector.inspect_runtime(executable);
    let (posture, reasons) = match facts {
        Ok(facts) => (
            posture_from_facts(&facts),
            facts
                .present_reasons()
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        Err(error) => (
            RuntimePosture::Unverifiable,
            vec![format!("inspection_failed: {error}")],
        ),
    };
    RuntimePostureReport {
        executable: executable.to_path_buf(),
        posture,
        reasons,
    }
}

/// Guard self-use binaries runtime posture check: the running guard-es plus
/// the deployed GUI and helper. Reports any retained debug/task exceptions in
/// the protection build (get-task-allow and friends must not ship).
pub fn guard_self_runtime_posture() -> Vec<RuntimePostureReport> {
    let mut candidates = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        candidates.push(current_exe);
    }
    for path in [
        "/Applications/Sensitive File Guard.app/Contents/MacOS/Guard",
        "/Applications/Sensitive File Guard.app/Contents/MacOS/guard-notify",
    ] {
        candidates.push(PathBuf::from(path));
    }
    candidates
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| runtime_posture_of(&path))
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInspection {
    pub valid: bool,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    /// SHA-1 of the leaf signing certificate. This is a stable local
    /// code-signing identity used in Security.framework requirements, not a
    /// per-build cdhash.
    pub leaf_certificate_sha1: Option<String>,
    pub cdhash: Vec<u8>,
    pub diagnostic: Option<String>,
}

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
            leaf_certificate_sha1: [0; 41],
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
            leaf_certificate_sha1: c_string(&raw.leaf_certificate_sha1),
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
    leaf_certificate_sha1: [std::ffi::c_char; 41],
    cdhash: [u8; 20],
    cdhash_len: usize,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct RawRuntimeInfo {
    has_entitlements: bool,
    get_task_allow: bool,
    allow_dyld_environment_variables: bool,
    disable_library_validation: bool,
    disable_executable_page_protection: bool,
    allow_unsigned_executable_memory: bool,
    allow_jit: bool,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn guard_code_signature_inspect(
        path: *const std::ffi::c_char,
        info: *mut RawSignatureInfo,
        error: *mut std::ffi::c_char,
        error_len: usize,
    ) -> i32;
    fn guard_code_signature_runtime_inspect(
        path: *const std::ffi::c_char,
        info: *mut RawRuntimeInfo,
        error: *mut std::ffi::c_char,
        error_len: usize,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_mapping_is_deterministic() {
        // Strong: verified entitlements with no security-relevant exceptions.
        let strong = RuntimeEntitlementFacts {
            has_entitlements: true,
            ..RuntimeEntitlementFacts::default()
        };
        assert_eq!(posture_from_facts(&strong), RuntimePosture::Strong);

        // allow-jit alone is narrow/legitimate => Strong (browser JIT).
        let jit_only = RuntimeEntitlementFacts {
            has_entitlements: true,
            allow_jit: true,
            ..RuntimeEntitlementFacts::default()
        };
        assert_eq!(posture_from_facts(&jit_only), RuntimePosture::Strong);

        // Any documented exception => Reduced.
        for facts in [
            RuntimeEntitlementFacts {
                has_entitlements: true,
                get_task_allow: true,
                ..RuntimeEntitlementFacts::default()
            },
            RuntimeEntitlementFacts {
                has_entitlements: true,
                allow_dyld_environment_variables: true,
                ..RuntimeEntitlementFacts::default()
            },
            RuntimeEntitlementFacts {
                has_entitlements: true,
                disable_library_validation: true,
                allow_jit: true,
                ..RuntimeEntitlementFacts::default()
            },
            RuntimeEntitlementFacts {
                has_entitlements: true,
                allow_unsigned_executable_memory: true,
                ..RuntimeEntitlementFacts::default()
            },
        ] {
            assert_eq!(posture_from_facts(&facts), RuntimePosture::Reduced);
        }

        // No entitlements dictionary => Unverifiable, never silently trusted.
        let unverifiable = RuntimeEntitlementFacts::default();
        assert_eq!(
            posture_from_facts(&unverifiable),
            RuntimePosture::Unverifiable
        );
    }

    #[test]
    fn present_reasons_label_allow_jit_as_narrow() {
        let facts = RuntimeEntitlementFacts {
            has_entitlements: true,
            allow_jit: true,
            ..RuntimeEntitlementFacts::default()
        };
        assert_eq!(
            facts.present_reasons(),
            vec!["allow-jit (narrow/legitimate)"]
        );
    }
}
