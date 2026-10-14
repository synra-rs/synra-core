//! Reading an event name out of a frame, and a kernel paired with its clock.


use synra_protocol::frame::Frame;


use super::record::Side;
use synra_protocol::frame::{FrameBody, FrameKind};

/// The event name inside an envelope frame, if it can be read.
///
/// Best effort: a frame the fixture cannot parse gives `None` rather than an error, because the reader here is an
/// assertion message and a fixture that failed to describe a frame would be less useful than one that says it could
/// not.
#[must_use]
pub fn frame_event(frame: &Frame) -> Option<String> {
    if frame.kind != FrameKind::Envelope {
        return None;
    }
    let FrameBody::Envelope(body) = &frame.body else {
        return None;
    };
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("event")?.as_str().map(str::to_owned)
}

/// A paired kernel's view of the other side, for a test that wants names rather than handles.
#[derive(Debug, Clone)]
pub struct PairedKernel {
    /// Which side it is.
    pub side: Side,
    /// The peer's device id, once it is known.
    pub peer_device_id: Option<String>,
    /// Whether the session completed its handshake.
    pub handshake_complete: bool,
}

impl PairedKernel {
    /// A side before anything has happened.
    #[must_use]
    pub const fn new(side: Side) -> Self {
        Self { side, peer_device_id: None, handshake_complete: false }
    }

    /// Records that the handshake completed with a peer.
    pub fn paired_with(&mut self, peer_device_id: impl Into<String>) {
        self.peer_device_id = Some(peer_device_id.into());
        self.handshake_complete = true;
    }

    /// Whether the session is up.
    #[must_use]
    pub const fn is_paired(&self) -> bool {
        self.handshake_complete && self.peer_device_id.is_some()
    }
}
