//! What the receiver sends back, and how the sender reads it.

use synra_protocol::session::TransferAbort;

use crate::link::{Inbound, LinkError, PeerLink};

use super::super::types::SessionError;
use super::super::wire::{Message, classify, payload_of};
use synra_protocol::session::TransferProgress;

/// A control message this session understands.
#[derive(Debug)]
pub(crate) enum Control {
    /// The receiver's report of what it holds.
    Progress(TransferProgress),
    /// The peer said it is finished.
    PeerFinished,
    /// Something this session cannot use.
    Unexpected(String),
}

/// Reads until a control message arrives, absorbing blocks on the way.
///
/// # Why blocks are consumed here rather than returned
///
/// Because this is the sending side: a block arriving at a sender belongs to a transfer this kernel is not running the
/// receiving end of, and there is nothing to do with it. Absorbing it keeps the stream moving instead of stopping the
/// transfer at the first stray frame.
pub(crate) fn read_control(link: &mut PeerLink) -> Result<Option<Control>, SessionError> {
    match link.receive_inbound() {
        // ★ A quiet link is "no message arrived", not a broken one. An earlier version propagated the timeout as
        // `LinkError::Transport`, so a transfer that had already moved every byte was reported as a link failure — which is
        // exactly what an end-to-end run showed. The caller's loop re-checks its own deadline, so the wait ends because the
        // caller said so.
        Err(LinkError::TimedOut) => {
            Ok(None)
        }
        Err(error) => Err(SessionError::Link(error)),
        Ok(Inbound::Block { .. }) => {
            Ok(Some(Control::Unexpected("a block at the sending end".to_owned())))
        }
        Ok(Inbound::Envelope(envelope)) => {
            match classify(&envelope) {
            Some(Message::Progress) => {
                let progress: TransferProgress = payload_of(&envelope, "progress")?;
                Ok(Some(Control::Progress(progress)))
            }
            Some(Message::Complete) => Ok(Some(Control::PeerFinished)),
            Some(Message::Abort) => {
                let abort: TransferAbort = payload_of(&envelope, "abort")?;
                Err(SessionError::Payload {
                    message: "abort",
                    why: format!("the peer gave up: {:?}", abort.reason),
                })
            }
            _ => Ok(None),
        }
        },
    }
}
