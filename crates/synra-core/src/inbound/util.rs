use crate::Inbound;
use crate::link::PeerLink;
use synra_protocol::session::TransferRequest;

/// Reads until a frame arrives or the deadline passes.
///
/// # Why a timeout is not reported
///
/// Because a link between two devices is idle most of the time, and the socket timeout is a short one — a read that waits
/// it out says nothing about whether the peer is still there. The deadline the caller owns is what bounds the wait, so a
/// message that arrives late is still read. Returning `Err` only for a link that has genuinely failed keeps "the peer went
/// away" meaning what it says.
///
/// # Errors
///
/// [`crate::LinkError`] for a link that failed rather than one that was quiet, and the same for a malformed frame.
pub(super) fn read_patiently(
    link: &mut PeerLink,
    deadline: std::time::Instant,
) -> Result<Inbound, crate::LinkError> {
    loop {
        // ★ The link's own timeout is capped by what is left of the caller's deadline, so "give up at five seconds" gives
        // up at five seconds rather than at the link's six. Without the cap this loop waited the link's whole timeout even
        // when the deadline had already passed, which is what made a bounded test hang.
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        link.set_read_timeout(Some(remaining));
        match link.receive_inbound() {
            Ok(inbound) => {
                link.set_read_timeout(None);
                return Ok(inbound);
            }
            Err(crate::LinkError::TimedOut) => {
                if std::time::Instant::now() >= deadline {
                    link.set_read_timeout(None);
                    return Err(crate::LinkError::TimedOut);
                }
            }
            Err(error) => {
                link.set_read_timeout(None);
                return Err(error);
            }
        }
    }
}

/// The file name a proposal carries.
/// The transfer request an envelope carries, parsed once for the name and the prompt.
pub(super) fn request_of(
    envelope: &synra_protocol::envelope::Envelope,
) -> Result<TransferRequest, crate::SessionError> {
    let raw = envelope
        .payload
        .as_ref()
        .ok_or_else(|| crate::SessionError::Payload {
            message: "request",
            why: "the envelope carries no payload".to_owned(),
        })?;
    serde_json::from_str(raw.get()).map_err(|error| crate::SessionError::Payload {
        message: "request",
        why: error.to_string(),
    })
}

/// The name an incoming transfer takes in the inbox.
pub(super) fn proposed_name(
    envelope: &synra_protocol::envelope::Envelope,
) -> Result<String, crate::SessionError> {
    let request = request_of(envelope)?;
    Ok(match request.meta {
        synra_protocol::session::TransferMeta::Attachment { file_name, .. } => file_name,
        // A plugin bundle is a `.synra` archive now, not a bare Wasm file: the receiver unpacks it, so the name in the
        // inbox has to say which kind of thing it is.
        synra_protocol::session::TransferMeta::PluginBundle { plugin_id, .. } => {
            format!("plugin-{plugin_id}.synra")
        }
        // `TransferMeta` is `#[non_exhaustive]`, so a kind this build does not know is named rather than guessed at — a
        // newer peer sending something this one cannot describe still gets a file rather than a failure.
        _ => "transfer".to_owned(),
    })
}
