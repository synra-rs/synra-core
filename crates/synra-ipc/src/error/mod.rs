//! The error that crosses the interface.
//!
//! # A message *key*, not a message
//!
//! The design document is explicit: `message` is a [`MessageKey`] plus `params`, not a sentence. A sentence
//! baked into a Rust error arrives in the user's language as English, and the only way to fix it later is to
//! change every error site — which by then is every file.
//!
//! So an error carrying text is a key like `error.capability_denied` and a bag of parameters. The interface owns
//! the translation, and the parameters are the values the sentence needs — a plugin's name, a capability's
//! string. That split also means the key and the parameters can be logged without the sentence, which is what
//! makes an error readable in a diagnostic bundle whose reader speaks a different language.
//!
//! # The code is what a caller branches on
//!
//! `code` uses the kernel's [`ErrorCode`](synra_protocol::ErrorCode). Two enums would drift, and the
//! drift would appear as a code the interface has no message for. Sharing it also means a refusal the kernel
//! already decided how to explain — whether it is worth showing the user, whether it is retryable — carries that
//! judgement across the boundary instead of being re-derived.

mod key;
mod report;

pub use key::{MAX_MESSAGE_KEY_LEN, MessageKey, MessageKeyError};
pub use report::IpcError;

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
