//! User-session pending helper lifecycle through macOS 13+ SMAppService.

use std::ffi::{c_char, CString};

use crate::DEFAULT_USER_AGENT_PLIST_NAME;

const ERROR_CAPACITY: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAgentStatus {
    NotRegistered,
    Enabled,
    RequiresApproval,
    NotFound,
}

pub struct UserAgentController {
    plist_name: CString,
}

impl UserAgentController {
    pub fn bundled() -> anyhow::Result<Self> {
        Self::new(DEFAULT_USER_AGENT_PLIST_NAME)
    }

    pub fn new(plist_name: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            plist_name.ends_with(".plist")
                && !plist_name.contains('/')
                && plist_name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                }),
            "invalid embedded LaunchAgent plist name"
        );
        Ok(Self {
            plist_name: CString::new(plist_name)?,
        })
    }

    pub fn status(&self) -> anyhow::Result<UserAgentStatus> {
        let raw = self.call_status(guard_user_agent_status)?;
        match raw {
            0 => Ok(UserAgentStatus::NotRegistered),
            1 => Ok(UserAgentStatus::Enabled),
            2 => Ok(UserAgentStatus::RequiresApproval),
            3 => Ok(UserAgentStatus::NotFound),
            _ => anyhow::bail!("SMAppService bridge returned invalid status {raw}"),
        }
    }

    pub fn register(&self) -> anyhow::Result<()> {
        self.call_mutation(guard_user_agent_register)
    }

    pub fn unregister(&self) -> anyhow::Result<()> {
        self.call_mutation(guard_user_agent_unregister)
    }

    pub fn open_system_settings() {
        // SAFETY: this function has no arguments and only asks the OS to open
        // its Login Items settings pane.
        unsafe { guard_user_agent_open_settings() }
    }

    fn call_status(
        &self,
        function: unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> i32,
    ) -> anyhow::Result<i32> {
        let mut error = [0 as c_char; ERROR_CAPACITY];
        // SAFETY: plist_name is NUL terminated and the error buffer remains
        // writable for this synchronous Objective-C call.
        let result = unsafe { function(self.plist_name.as_ptr(), error.as_mut_ptr(), error.len()) };
        anyhow::ensure!(result >= 0, "SMAppService failed: {}", c_error(&error));
        Ok(result)
    }

    fn call_mutation(
        &self,
        function: unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> i32,
    ) -> anyhow::Result<()> {
        let result = self.call_status(function)?;
        anyhow::ensure!(result == 0, "SMAppService mutation returned {result}");
        Ok(())
    }
}

fn c_error(buffer: &[c_char]) -> String {
    let bytes = buffer
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}

extern "C" {
    fn guard_user_agent_status(
        plist_name: *const c_char,
        error_buffer: *mut c_char,
        error_buffer_length: usize,
    ) -> i32;
    fn guard_user_agent_register(
        plist_name: *const c_char,
        error_buffer: *mut c_char,
        error_buffer_length: usize,
    ) -> i32;
    fn guard_user_agent_unregister(
        plist_name: *const c_char,
        error_buffer: *mut c_char,
        error_buffer_length: usize,
    ) -> i32;
    fn guard_user_agent_open_settings();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_plist_name_is_narrow() {
        assert!(UserAgentController::new("io.example.Guard.guard-notify.plist").is_ok());
        assert!(UserAgentController::new("../LaunchAgents/evil.plist").is_err());
        assert!(UserAgentController::new("missing-suffix").is_err());
    }
}
