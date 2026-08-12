//! Native macOS notification delivery for the user-session helper.

use std::ffi::{c_char, CString};

const ERROR_CAPACITY: usize = 512;

pub fn send(title: &str, body: &str) -> anyhow::Result<()> {
    let title = CString::new(title)?;
    let body = CString::new(body)?;
    let mut error = [0 as c_char; ERROR_CAPACITY];
    // SAFETY: the C strings and writable diagnostic buffer remain valid for
    // the synchronous Foundation/AppKit call.
    let result = unsafe {
        guard_user_notification(
            title.as_ptr(),
            body.as_ptr(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    anyhow::ensure!(result == 0, "{}", c_error(&error));
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn notification_text_is_metadata_only() {
        let body = "A process was blocked from accessing protected browser_cookie_store.";
        assert!(!body.contains("/Users/"));
        assert!(!body.contains("Cookie"));
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

unsafe extern "C" {
    fn guard_user_notification(
        title: *const c_char,
        body: *const c_char,
        error_buffer: *mut c_char,
        error_buffer_length: usize,
    ) -> i32;
}
