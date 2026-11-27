//! Bounds for text handed to the desktop platform.

use crate::actions::MAX_NOTIFICATION_LEN;
use crate::error::PlatformError;

/// Check the shared UTF-8 byte budget before writing clipboard text.
///
/// # Errors
/// [`PlatformError::TooLong`] when the encoded text exceeds [`crate::MAX_CLIPBOARD_BYTES`].
pub const fn check_clipboard_text(text: &str) -> Result<(), PlatformError> {
    if text.len() > crate::MAX_CLIPBOARD_BYTES {
        return Err(PlatformError::TooLong {
            field: "clipboard text in UTF-8 bytes",
            len: text.len(),
            max: crate::MAX_CLIPBOARD_BYTES,
        });
    }
    Ok(())
}

/// Checks a notification's text.
///
/// # Errors
///
/// [`PlatformError::TooLong`].
pub fn check_notification(title: &str, body: &str) -> Result<(), PlatformError> {
    for (field, text) in [("notification title", title), ("notification body", body)] {
        let len = text.chars().count();
        if len > MAX_NOTIFICATION_LEN {
            return Err(PlatformError::TooLong { field, len, max: MAX_NOTIFICATION_LEN });
        }
    }
    Ok(())
}
