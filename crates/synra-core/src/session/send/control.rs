//! Typed receiver messages; unrelated traffic cannot complete a transfer.

use synra_protocol::session::{TransferAbort, TransferComplete, TransferProgress};

use super::super::types::SessionError;
use super::super::wire::{Message, classify, payload_of};
use crate::link::{Inbound, LinkError, PeerLink};

pub(super) enum Control {
    Progress(TransferProgress),
    Complete(TransferComplete),
    Abort(TransferAbort),
}

pub(super) fn read_control(link: &mut PeerLink) -> Result<Option<Control>, SessionError> {
    match link.receive_inbound() {
        Err(LinkError::TimedOut) => Ok(None),
        Err(error) => Err(error.into()),
        Ok(Inbound::Block { .. }) => Err(SessionError::Payload {
            message: "control",
            why: "a block arrived at the sending end".to_owned(),
        }),
        Ok(Inbound::Envelope(envelope)) => match classify(&envelope) {
            Some(Message::Progress) => {
                Ok(Some(Control::Progress(payload_of(&envelope, "progress")?)))
            }
            Some(Message::Complete) => {
                Ok(Some(Control::Complete(payload_of(&envelope, "complete")?)))
            }
            Some(Message::Abort) => Ok(Some(Control::Abort(payload_of(&envelope, "abort")?))),
            _ => Err(SessionError::Payload {
                message: "control",
                why: format!("unexpected event {}", envelope.event),
            }),
        },
    }
}
