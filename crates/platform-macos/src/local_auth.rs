//! LocalAuthentication gate for macOS capability-expanding operations.

use std::ffi::{c_char, CString};
use std::time::Instant;

const ERROR_CAPACITY: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationFailure {
    Cancelled,
    TimedOut,
    Unavailable,
    Failed,
}

impl std::fmt::Display for AuthenticationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(formatter, "device-owner authentication was cancelled"),
            Self::TimedOut => write!(formatter, "device-owner authentication timed out"),
            Self::Unavailable => write!(formatter, "device-owner authentication is unavailable"),
            Self::Failed => write!(formatter, "device-owner authentication failed"),
        }
    }
}

#[derive(Debug)]
pub struct AuthenticationError {
    pub failure: AuthenticationFailure,
    pub diagnostic: String,
}

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.failure, self.diagnostic)
    }
}

impl std::error::Error for AuthenticationError {}

/// Injectable boundary used by the typed client. Production construction is
/// backed by `LAContext + LAPolicyDeviceOwnerAuthentication`.
pub trait DeviceOwnerAuthenticator: Send + Sync {
    fn authenticate(&self, reason: &str, deadline: Instant) -> Result<(), AuthenticationError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct NativeDeviceOwnerAuthenticator;

impl DeviceOwnerAuthenticator for NativeDeviceOwnerAuthenticator {
    fn authenticate(&self, reason: &str, deadline: Instant) -> Result<(), AuthenticationError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| AuthenticationError {
                failure: AuthenticationFailure::TimedOut,
                diagnostic: "pending Endpoint Security deadline already elapsed".into(),
            })?;
        let milliseconds = u64::try_from(remaining.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let reason = CString::new(reason).map_err(|_| AuthenticationError {
            failure: AuthenticationFailure::Failed,
            diagnostic: "authentication reason contains a NUL byte".into(),
        })?;
        let mut error = [0 as c_char; ERROR_CAPACITY];
        // SAFETY: both C strings are valid for the synchronous Objective-C
        // call; the output buffer is writable for its declared capacity.
        let result = unsafe {
            guard_local_authenticate(
                reason.as_ptr(),
                milliseconds,
                error.as_mut_ptr(),
                error.len(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let diagnostic = c_error(&error);
        let failure = match result {
            1 => AuthenticationFailure::Cancelled,
            2 => AuthenticationFailure::TimedOut,
            3 => AuthenticationFailure::Unavailable,
            _ => AuthenticationFailure::Failed,
        };
        Err(AuthenticationError {
            failure,
            diagnostic,
        })
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
    fn guard_local_authenticate(
        localized_reason: *const c_char,
        timeout_milliseconds: u64,
        error_buffer: *mut c_char,
        error_buffer_length: usize,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elapsed_deadline_never_opens_local_authentication() {
        let error = NativeDeviceOwnerAuthenticator
            .authenticate("Synthetic allow", Instant::now())
            .unwrap_err();
        assert_eq!(error.failure, AuthenticationFailure::TimedOut);
    }
}
