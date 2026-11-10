use synra_protocol::error::ErrorCode;

use crate::Response;

/// A refusal the kernel is reporting.
///
/// # Why the code is the protocol's `ErrorCode` rather than a string
///
/// Because a string is a second spelling of a name that already exists, and the two drift at the first rename — with
/// the failure landing in a client that branches on a code the kernel no longer sends. Using the protocol's type also
/// gives the *retryable* flag for free: whether a failure is worth repeating is a property of the code, and a kernel
/// that decided for itself would be a second opinion that can contradict the one every other part of the system uses.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct Refusal {
    /// The kernel's stable error code.
    pub code: ErrorCode,
    /// A sentence for a person.
    ///
    /// # Why a sentence here and a key at the interface
    ///
    /// The interface renders a *message key* because it knows the user's language. A command-line client does not: it
    /// prints, and its output goes to a terminal rather than to a translated screen. So the sentence is composed here,
    /// where the detail is, and the interface's boundary keeps its keys.
    pub message: String,
}

impl Refusal {
    /// A refusal with a sentence.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Whether repeating the request as it was could succeed.
    ///
    /// Read from the code rather than stored, so a refusal cannot claim to be retryable when its code says otherwise.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.code.retryable()
    }
}

impl From<Refusal> for Response {
    fn from(refusal: Refusal) -> Self {
        // Read before the message is moved out: `is_retryable` borrows the refusal, and the message is a field of it.
        let retryable = refusal.is_retryable();
        // ★ The code's wire spelling, which is the same string the interface, the device protocol and the plugin
        // boundary use. A second spelling here would be a code a script matches on that appears nowhere else.
        Self::failed(refusal.code.as_str(), refusal.message, retryable)
    }
}
