//! File and bundle entry points to the shared complete sending workflow.

use std::path::Path;

use synra_protocol::session::SriDigest;

use crate::link::PeerLink;
use crate::transfer::TransferSender;

use super::super::types::{SessionError, SessionEvent};
use super::prepared::{SendOptions, send_prepared};
use synra_protocol::ids::TraceId;

/// The one-shot send: propose, move every block, complete, and wait for the confirmation.
///
/// # Errors
///
/// [`SessionError`] for link, file, payload, refusal, or deadline failures; success requires receiver confirmation.
pub fn send_file(
    link: &mut PeerLink,
    path: &Path,
    chunk_size: u32,
    trace_id: TraceId,
    now_ms: i64,
    deadline: std::time::Instant,
) -> Result<Vec<SessionEvent>, SessionError> {
    let mut sender = TransferSender::open(path, chunk_size)?;
    send_prepared(
        link,
        &mut sender,
        SendOptions::new(trace_id, now_ms, deadline),
        || false,
        |_, _| {},
    )
}

/// Reads a digest's algorithm and value, for a report.
#[must_use]
pub fn describe(digest: &SriDigest) -> String {
    format!("{}:{}", digest.algorithm().prefix(), digest.encoded())
}

/// A bundle's one-shot send: the same four steps, with a request that says what it is.
///
/// # Why a second function rather than an argument on [`send_file`]
///
/// The two differ in exactly one thing — the metadata the receiver builds its decision from — and that one thing is
/// decided by *what is being sent*, not by how the transfer runs. An `Option<PluginId>` on `send_file` would make every
/// existing caller state which of the two they meant, in a signature about bytes rather than about plugins.
///
/// # Errors
///
/// The same as [`send_file`]: any failure of the link, the file or the messages.
pub fn send_bundle(
    link: &mut PeerLink,
    path: &Path,
    round: &crate::plugin_sync::SyncRound,
    trace_id: TraceId,
    now_ms: i64,
    deadline: std::time::Instant,
) -> Result<Vec<SessionEvent>, SessionError> {
    // The chunk size is the kernel's rather than the caller's, which is why this takes one argument fewer than
    // `send_file`: a bundle is sent by the daemon on a plugin's behalf, and neither of them has a view about how many
    // bytes should travel in one block.
    let mut sender = TransferSender::open_bundle(path, crate::transfer::DEFAULT_CHUNK_SIZE, round)?;
    send_prepared(
        link,
        &mut sender,
        SendOptions::new(trace_id, now_ms, deadline),
        || false,
        |_, _| {},
    )
}
