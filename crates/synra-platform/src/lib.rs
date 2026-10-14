//! Host system capabilities, and the rules that bound them.
//!
//! # This is the most dangerous surface in the application
//!
//! Everything else a plugin can do is mediated: `device:send` goes to another Synra device, `fs:write` goes into
//! a sandbox directory, `network:fetch` goes through a host that can refuse a hostname. `platform:*` goes to the
//! user's actual machine — it opens their browser, types into their other applications, reads their clipboard.
//!
//! A bug here is not a plugin misbehaving inside its own boundaries. It is a plugin acting as the user.
//!
//! # The rules are values, not calls
//!
//! [`Policies`] holds every decision — whether an executable may be opened, whether a plain-HTTP URL is allowed,
//! how often a notification may fire — and [`Platform::check`] answers yes or no without touching the operating
//! system. That shape is deliberate: the interesting part of this module is *whether a call should happen*, and
//! a design that only answers that question by attempting the call is a design whose rules cannot be tested.
//!
//! So there are two halves:
//!
//! * **Decide** — [`Policies::check`] and friends. Pure, exhaustively tested, and the place where a mistake is a
//!   unit test rather than an incident.
//! * **Act** — the [`Platform`] trait. Thin, unimplemented here, and implemented by the application layer over
//!   Tauri.
//!
//! # Every action is separate, and none is implied by another
//!
//! # Why this is a directory and not a file
//!
//! Because it holds five separable things: what a host action *is* and how far the host's permissions reach, what a
//! refusal *says*, the checks that decide a refusal, the rate limiter those checks use, and the trait a real host
//! implements. In one file the trait — the part a reader most needs to see whole — sat after a thousand lines of
//! validation.
//!
//! | Module | Holds |
//! | --- | --- |
//! | `actions` | the actions, the constants that bound them, and the policies |
//! | `error` | why an action was refused, and the two narrow refusals |
//! | `guard` | the checks, and the rate limiter |
//! | `host` | the `Platform` trait and the headless implementation |

#![forbid(unsafe_code)]
#![warn(missing_docs)]

// Test code is exempt from the no-panic rules; see `synra-protocol` for the reasoning. The relaxation has to live
// at the crate root, because the workspace sets these lints to `deny` and a local `#[allow]` cannot override a
// `deny` set at a higher priority level.
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

pub mod actions;
pub mod error;
pub mod guard;
pub mod host;

pub use actions::{
    Policies, PlatformAction, EXECUTABLE_EXTENSIONS, MAX_CHORD_LEN, MAX_CLIPBOARD_BYTES,
    MAX_NOTIFICATION_LEN, MAX_URL_LEN,
};
pub use error::{PathRefusal, PlatformError, UrlRefusal};
pub use guard::{
    RateLimiter, check_key_chord, check_notification, check_path, check_url, check_url_length,
};
pub use host::{HeadlessPlatform, Platform};

#[cfg(test)]
mod proptests;

#[cfg(test)]
mod tests;