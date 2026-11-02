//! The wire tap: one line for every frame a link writes or reads.
//!
//! # Why this is a process-wide sink rather than a field on a link
//!
//! The interface wants **all** traffic, and links are built in more than one place: a dialled link belongs to the command
//! that started it, an accepted link belongs to the listener's host, and the two do not share a caller. Threading a sink
//! through every constructor would make "show me the wire" a parameter of the transport, which is the opposite of an
//! observability feature.
//!
//! # Why a missing sink costs nothing
//!
//! [`emit`] checks for a sink before it formats anything. A release build with the debug console closed is a load and a
//! branch per frame, not a `format!` per frame — the tap must not become the reason a transfer is slow.
//!
//! # Why the tap cannot change what travels
//!
//! It is given an already-written or already-parsed frame. It cannot rewrite bytes, refuse a send, or delay a read; the
//! worst it can do is a slow callback, and the sink the shell installs only pushes onto a bounded channel.

use std::sync::{Arc, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Which way a traced frame travelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireDirection {
    /// This device wrote it.
    Sent,
    /// This device read it.
    Received,
    /// Neither: a lifecycle note, such as a dial that never produced a link.
    Note,
}

impl WireDirection {
    /// The word a terminal shows.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
            Self::Note => "note",
        }
    }
}

/// One line of wire traffic.
///
/// `peer` is text rather than a `DeviceId` so this crate does not grow a protocol dependency for a debug view; the caller
/// already has the identifier and its `Display` is the only thing the terminal needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireEvent {
    /// When it happened, in milliseconds since the Unix epoch.
    pub at_ms: i64,
    /// Which way it travelled.
    pub direction: WireDirection,
    /// The device on the other end, or `local` for a note that has no peer.
    pub peer: String,
    /// What it was: an event name, `chunk`, or a note's own short label.
    pub label: String,
    /// Payload bytes. Zero for a note.
    pub bytes: usize,
}

impl WireEvent {
    /// A frame this device sent.
    #[must_use]
    pub fn sent(peer: impl Into<String>, label: impl Into<String>, bytes: usize) -> Self {
        Self::new(WireDirection::Sent, peer, label, bytes)
    }

    /// A frame this device received.
    #[must_use]
    pub fn received(peer: impl Into<String>, label: impl Into<String>, bytes: usize) -> Self {
        Self::new(WireDirection::Received, peer, label, bytes)
    }

    /// A lifecycle line that is not a frame.
    #[must_use]
    pub fn note(peer: impl Into<String>, label: impl Into<String>) -> Self {
        Self::new(WireDirection::Note, peer, label, 0)
    }

    fn new(
        direction: WireDirection,
        peer: impl Into<String>,
        label: impl Into<String>,
        bytes: usize,
    ) -> Self {
        Self {
            at_ms: now_ms(),
            direction,
            peer: peer.into(),
            label: label.into(),
            bytes,
        }
    }
}

/// What the shell installs to receive the tap.
pub type WireSink = Arc<dyn Fn(&WireEvent) + Send + Sync>;

/// The process-wide sink, absent until somebody asks for the wire.
static SINK: OnceLock<RwLock<Option<WireSink>>> = OnceLock::new();

fn slot() -> &'static RwLock<Option<WireSink>> {
    SINK.get_or_init(|| RwLock::new(None))
}

/// Installs the sink, returning whether one was already there.
///
/// Replacing rather than refusing is deliberate: a window that reloads its interface is one process installing a second
/// sink, and the old one belongs to a webview that no longer exists.
pub fn install(sink: WireSink) -> bool {
    let mut guard = slot().write().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.replace(sink).is_some()
}

/// Removes the sink, if any.
pub fn clear() -> bool {
    let mut guard = slot().write().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.take().is_some()
}

/// Whether anything is listening.
#[must_use]
pub fn is_installed() -> bool {
    slot()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

/// Hands one event to the sink.
///
/// The lock is released before the callback runs. A sink that called back into [`emit`] would otherwise deadlock on a
/// read lock it already holds, and a debug feature that can hang the transport is worse than no debug feature.
pub fn emit(event: WireEvent) {
    let sink = {
        let guard = slot().read().unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.as_ref().map(Arc::clone)
    };
    if let Some(sink) = sink {
        sink(&event);
    }
}

/// A note, for a caller that does not want to build the struct.
pub fn note(peer: impl Into<String>, label: impl Into<String>) {
    if is_installed() {
        emit(WireEvent::note(peer, label));
    }
}

/// Milliseconds since the Unix epoch.
///
/// Saturating: a clock before 1970 is a broken clock, and a debug line stamped zero is more useful than a panic in a
/// transport path.
#[must_use]
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sent_event_names_its_direction_and_size() {
        let event = WireEvent::sent("dev_b", "_synra.pair.request", 42);
        assert_eq!(event.direction, WireDirection::Sent);
        assert_eq!(event.direction.as_str(), "sent");
        assert_eq!(event.peer, "dev_b");
        assert_eq!(event.bytes, 42);
        assert!(event.at_ms > 0);
    }

    #[test]
    fn a_note_has_no_payload() {
        let event = WireEvent::note("local", "dial failed");
        assert_eq!(event.direction.as_str(), "note");
        assert_eq!(event.bytes, 0);
    }

    #[test]
    fn installing_replaces_and_clear_reports_what_it_removed() {
        let first = Arc::new(|_: &WireEvent| {});
        let second = Arc::new(|_: &WireEvent| {});
        // A sink can outlive another test in the same binary, so the starting point is established rather than assumed.
        clear();
        assert!(!install(first));
        assert!(install(second));
        assert!(is_installed());
        assert!(clear());
        assert!(!clear());
        assert!(!is_installed());
    }
}