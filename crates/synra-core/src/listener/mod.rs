//! The listening half of the session layer.
//!
//! # Why a kernel needs this at all
//!
//! [`crate::Host::dial`] makes an *outbound* link, and a device that can only dial is a device nobody can send to. The
//! announcement every device broadcasts carries a port, and that port is this: a TCP listener that accepts an inbound
//! connection, completes a handshake, and reads what arrives on it.
//!
//! # The shape of the loop, and why it is two phases
//!
//! Taking a connection and handshaking on it are wildly different lengths — a queue pop against a read with a six-second
//! timeout. So the loop **pops** under the host's lock, which is cheap, and hands the socket to a thread that handshakes on
//! it. A loop that did both would hold the host for as long as a peer took to say `Hello`, and a peer that connected and
//! then went silent would freeze `devices` for six seconds — the report a user runs *while* something is wrong.
//!
//! # Why an inbound message is only reported
//!
//! Because there is nowhere to put it yet: the event bus, the plugin host and the interface are all downstream of this, and
//! a message that arrived has to reach them. What this establishes is the part that can be established now — that a peer
//! can connect, that the handshake identifies it, that an envelope arrives and passes the link's checks, and that the
//! session is recorded. Reporting it is the honest end of that chain rather than pretending to deliver it.
//!
//! # Why the accept loop never stops on an error
//!
//! Because the errors it can see are all about *one* connection: a peer that disconnected mid-handshake, a port scan, a
//! malformed frame. A listener that exited on any of those would be one any process on the network could stop.

mod accept;
mod connection;
mod delivered;
mod events;
mod late;
mod messages;
mod pairing;
mod traffic;
mod types;

pub use crate::inbound::{Decision, Inbox};
pub use accept::{bind, is_open, serve, serve_with};
pub use connection::{handle, handle_with, handle_within, handle_within_with};
pub use late::retry_late;
pub use types::{
    CancelCallback, FinishedCallback, FinishedTransfer, InboundProgressEvent, KernelEventCallback,
    KernelEventOutcome, ProgressCallback, Served, no_answer, no_kernel_events,
};

use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_millis(50);
const PATIENCE: Duration = synra_protocol::limits::HELLO_TIMEOUT;

/// Why a connection ended, as the label of `links_closed_total`.
fn close_reason(error: &crate::SessionError) -> &'static str {
    match error {
        crate::SessionError::Link(crate::link::LinkError::Unauthorized) => "authorization",
        crate::SessionError::Link(crate::link::LinkError::AuthorizationUnavailable { .. }) => {
            "authorization_storage"
        }
        crate::SessionError::Link(crate::link::LinkError::TimedOut) => "timeout",
        crate::SessionError::Link(crate::link::LinkError::Closed) => "closed",
        crate::SessionError::Link(
            crate::link::LinkError::Frame(_)
            | crate::link::LinkError::Unexpected { .. }
            | crate::link::LinkError::Envelope { .. },
        ) => "protocol",
        crate::SessionError::Link(crate::link::LinkError::Transport { .. }) => "transport",
        crate::SessionError::Transfer(_) => "transfer",
        _ => "protocol",
    }
}
