use std::sync::Arc;

use synra_protocol::envelope::Envelope;

/// What one accepted connection produced.
#[derive(Debug, Clone, PartialEq, Eq)]
/// A transfer that finished and whose file was verified.
///
/// ★ **Why the listener hands these back rather than only logging them.**
///
/// `Decision::Finished` is where a received file stops being bytes, and until this existed the only thing the listener
/// could do with a plugin bundle was print a line — the kernel received one and forgot it. `SyncRecord` grew the fields
/// for a record in round 133, migration v10 gave it a table in round 135, and round 136 wrote the conversion between
/// them; all three have had no production caller, and this is why: the place a transfer finishes had nothing to write
/// **to**. This is the value that travels from that place to a caller that has a database.
pub struct FinishedTransfer {
    /// Which transfer it was.
    ///
    /// `None` only for a completion that arrived with no proposal this listener saw, which is a protocol violation rather
    /// than a transfer — and a row named by a made-up identifier would be worse than no row. The shell uses this to close
    /// the progress row it opened when the proposal was accepted.
    pub transfer_id: Option<synra_protocol::ids::TransferId>,
    /// Where the file landed.
    pub path: std::path::PathBuf,
    /// How large it was.
    pub byte_length: u64,
    /// Which plugin it is a bundle for, when it is one.
    pub bundle: Option<synra_protocol::ids::PluginId>,
    /// The digest this device verified the file against.
    pub digest: String,
    /// The version the sender declared, when this arrived as a plugin bundle.
    pub version: Option<String>,
    /// Which round this belonged to, when the sender named one.
    pub sync_session_id: Option<synra_protocol::ids::SessionId>,
    /// Which device it came from.
    ///
    /// Carried per transfer rather than read off `Served::peer` by the caller: `peer` is a fact about the *connection*
    /// and this is a fact about the *file*, and a caller writing history would otherwise need to hold both pieces
    /// together to know who sent what.
    pub peer: synra_protocol::ids::DeviceId,
}

/// One step of an inbound transfer, for a reporter that keeps a row in an interface.
///
/// The peer is here rather than inside `progress` because it is a fact about the connection, not about the bytes — the
/// receiver writes to a path and knows nothing about who is on the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundProgressEvent {
    /// Who is sending.
    pub peer: synra_protocol::ids::DeviceId,
    /// How far the transfer has got.
    pub progress: crate::session::InboundProgress,
    /// The transfer ended without a file: the peer aborted, or a block was refused.
    ///
    /// ★ The last event of a failed transfer is still an event. Without it a reporter that opened a row for
    /// [`InboundProgress`] would keep it for ever — the sender's abort would be a row that says "arriving" until the
    /// process ends.
    pub aborted: bool,
}

/// What the listener does with each step of an inbound transfer.
///
/// `Send + Sync` for the same reason [`FinishedCallback`] is: the connections that call it live on their own threads, and
/// one callback is shared by all of them.
pub type ProgressCallback = dyn Fn(&InboundProgressEvent) + Send + Sync;

/// Whether the host wants the transfer in progress given up.
///
/// ★ Asked between messages, never from another thread: the connection's own loop is the only writer to its link, and a
/// command that could send an abort from outside would be a second writer to one socket.
pub type CancelCallback = dyn Fn(&str) -> bool + Send + Sync;

/// A cancel callback for a host that does not offer one.
pub(super) fn no_cancel() -> Arc<CancelCallback> {
    Arc::new(|_: &str| false)
}

/// What a host did with a kernel event that arrived on a link.
#[derive(Debug)]
#[non_exhaustive]
pub enum KernelEventOutcome {
    /// The host does not handle this event.
    Ignored,
    /// The host handled it, and there is nothing to send back.
    Handled,
    /// The answer to send back on the same link.
    Reply(Box<Envelope>),
    /// Queue admission receipt; send on the requesting link only, never dial back or persist as an outcome.
    Receipt(Box<Envelope>),
    /// The event was understood and refused, with a sentence for the log.
    Refused(String),
}

/// Answers a kernel event (`INTENT_INVOKE`, `INTENT_CANCEL`) that arrived on a link.
///
/// # Why a callback rather than code here
///
/// Because running an action needs the plugin set and the intent board, which belong to the host; the listener owns the
/// connection, not the runtime. The callback is the same seam `FinishedCallback` uses, and it exists for the same reason:
/// a reply belongs on the connection that asked, so the answer has to be produced **while the link is still open**.
/// The captured authority accompanies the envelope so deferred consumers can recheck it without
/// refreshing the connection to a newer approval. The listener refuses unauthenticated links.
pub type KernelEventCallback =
    dyn Fn(&Envelope, &synra_protocol::ids::DeviceId) -> KernelEventOutcome + Send + Sync;

/// A kernel-event callback for a host that runs no kernel events.
#[must_use]
pub fn no_kernel_events() -> Arc<KernelEventCallback> {
    Arc::new(
        |_event: &Envelope, _authority: &synra_protocol::ids::DeviceId| KernelEventOutcome::Ignored,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// What one connection did, handed back to whoever served it.
///
/// `events` is the count a test asserts and `finished` is the value a caller writes down; `ended` is how a session
/// that went wrong ended, and is `None` for the ordinary case of a peer that hung up.
pub struct Served {
    /// The device on the other end, when the handshake established one.
    ///
    /// `None` for a connection that failed before `Hello` — which is the ordinary shape of a port scan and of a peer that
    /// connected and went silent. A sentinel identifier would be one a caller could mistake for a real device, and a
    /// device whose identifier is all zeroes is not a device.
    pub peer: Option<synra_protocol::ids::DeviceId>,
    /// The event names that arrived, in order.
    ///
    /// Names rather than the envelopes, because an envelope holds a `RawValue` payload and a caller that is only reporting
    /// does not need it. The count is what a test asserts; the names are what a log line says.
    pub events: Vec<String>,
    /// How the session ended, when it ended badly.
    pub ended: Option<String>,
    /// Every transfer that finished and verified on this connection, in order.
    pub finished: Vec<FinishedTransfer>,
}

/// What the connection handler asks the host to do about a transfer that just finished.
///
/// ★ **Why the three arguments are named rather than written out three times.** The signature appeared in `serve`,
/// `handle` and `handle_within`, and clippy's `type_complexity` was right about it: three copies of a type nobody can
/// read is three places to change and one place to understand.
///
/// ★ **Why it returns an answer rather than nothing.** It is called while the connection is still open, and what it
/// returns is what the sender is told. `None` means "there is nothing to say" — an attachment is not a round of
/// synchronisation, so it has no result.
pub type FinishedCallback =
    Arc<dyn Fn(&FinishedTransfer) -> Option<crate::plugin_sync::SyncOutcome> + Send + Sync>;

/// A callback that answers nothing.
///
/// For a host with no opinion about what it received — a test, or a build that only wants the file on disk. It is a
/// named function rather than a closure written at each call site because the type is the unreadable part, and three
/// spellings of it would be three places to change.
#[must_use]
pub fn no_answer() -> FinishedCallback {
    Arc::new(|_| None)
}
