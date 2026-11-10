//! Keeping secrets out of logs.
//!
//! The list of things that must never reach a log file is short and absolute:
//!
//! * clipboard contents
//! * message payload bodies
//! * file contents
//! * keys and tokens
//! * the query and fragment of a URL, which routinely carry a token
//! * a plugin's secure-storage values
//!
//! This module is the one place that enforces it. A `tracing` filter could drop whole events, but the
//! problem is not whole events: it is one field inside an otherwise useful log line. Dropping the line
//! loses the diagnosis; keeping the field leaks the secret.
//!
//! # Two mechanisms, because the failure modes differ
//!
//! * **A denylist of field names** replaces the value entirely. This is the primary defence, because a
//!   developer writing `info!(payload = ?body, "received")` has made a mistake they can fix, and the
//!   name is what tells us the value is dangerous.
//! * **A length cap** truncates everything else. This is the backstop for the case the denylist cannot
//!   cover: a secret logged under a name nobody anticipated. It does not prevent the leak, but it bounds
//!   it, and a bounded leak in a bug report is a different problem from an unbounded one.
//!
//! # Why the denylist checks substrings
//!
//! Field names are written by hand and come in flavours: `payload`, `payloadLen`, `request_body`,
//! `authToken`, `api_key`, `userSecret`. Matching whole names would miss most of them, and the miss is
//! silent. Substring matching over-redacts instead — `body_count` becomes `<redacted>` — and an
//! over-redacted log is a small annoyance where an under-redacted one is a security incident.
//!
//! # URLs are handled separately
//!
//! A URL is usually safe to log and usually necessary to log. What is not safe is its query string:
//! `?token=…`, `?access_token=…`, `?code=…`. So a URL keeps its scheme, host and path and loses
//! everything from `?` or `#`.

mod policy;
mod result;
mod url;

pub use policy::Redactor;
pub use result::{Redacted, Redaction};

/// The replacement written in place of a redacted value.
pub const REDACTED: &str = "<redacted>";

/// The suffix appended to a truncated value, with its original length.
///
/// The length is kept because it is frequently the diagnostic detail that matters — "the header was
/// 4 KB" — while the bytes are what must not be kept.
pub const TRUNCATION_MARK: &str = "…";

/// The default cap on an ordinary string value.
pub const DEFAULT_MAX_VALUE_LEN: usize = 512;

#[cfg(test)]
mod proptests;
#[cfg(test)]
mod tests;
