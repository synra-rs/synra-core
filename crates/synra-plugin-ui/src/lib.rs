//! UI plugin artifacts, and the session tokens that gate their calls.
//!
//! # Two halves, and only one of them is about files
//!
//! A UI plugin ships an artifact — a bundle of files with an entry document. Managing it is bookkeeping: which files
//! a version contains, whether the entry exists, how large the bundle is.
//!
//! The other half is [the session registry](session), and it is the security-relevant one. A plugin's page runs in a
//! WebView, calls the kernel over IPC, and is code from a stranger. Three things must not be possible, and the design
//! document names them:
//!
//! * Forging its own `pluginId` — a call carries a nonce *and* a claimed plugin, and both must agree.
//! * Calling another plugin's capabilities — which is the first one, caught.
//! * Calling after being deactivated — the kernel cannot stop a WebView, so it revokes the token and every later
//!   call fails.
//!
//! # What is deliberately not here
//!
//! **No rendering, no WebView, no serving.** The application owns those, and a crate that knew about a window could
//! not be tested without one. What is here is the decision — may this call proceed — which is the part that gets the
//! answer wrong in a way nobody notices.
//!
//! # The token never reaches the page
//!
//! The nonce is injected into the plugin's WebView as a closure variable and not as a property of `window`. The
//! module docs of [`session`] explain why: a property can be read by the plugin's own code, and a token the plugin
//! can read is a token it can hand to another page.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::needless_pass_by_value,
    )
)]

pub mod artifact;
pub mod session;

pub use artifact::{
    ArtifactError, ArtifactFile, UiArtifact, UiArtifactIndex, MAX_ARTIFACT_BYTES, MAX_ARTIFACT_FILES,
};
pub use session::{
    SESSION_LIFETIME_MS, SessionRefusal, SessionReport, UiSessionRegistry, UiSessionToken,
    ValidatedSession,
};