use synra_control::Refusal;
use synra_core::HostError;
use synra_protocol::error::ErrorCode;

/// A `HostError` as a refusal a client can act on.
///
/// # Why each failure gets its own code
///
/// Because the user's next step differs: a name nothing matches is a typo, an ambiguous name is a decision they have to
/// make, an unreachable device is one that is switched off, and a handshake failure is a network. One code for all of them
/// would leave the client unable to say anything but the message the kernel wrote.
pub(super) fn refusal_of(error: &HostError) -> Refusal {
    let code = match error {
        // Nothing is called that. `NotPaired` rather than a "not found": what the kernel knows about is devices it has
        // seen, and one it has never seen is one it is not paired with — which is the fact the user can act on.
        HostError::NoSuchDevice { .. } => ErrorCode::NotPaired,
        // Known by name and never seen, so there is no address to dial.
        HostError::Unreachable { .. } => ErrorCode::DeviceOffline,
        // More than one matched, which is a decision the user has to make rather than a fault.
        HostError::AmbiguousName { .. } => ErrorCode::InvalidArgument,
        // The device is there and the two cannot work together, which is a version problem rather than a network one.
        HostError::Incompatible { .. } => ErrorCode::Unsupported,
        // A handshake or a link failure is the network.
        HostError::Handshake(_) | HostError::Link(_) | HostError::Bind { .. } => ErrorCode::TransportNotOpen,
        HostError::NoSession(_) => ErrorCode::NotPaired,
        // `#[non_exhaustive]`: a failure this build does not know is still a failure, and `Internal` is the honest code
        // for one it cannot name.
        _ => ErrorCode::Internal,
    };
    Refusal::new(code, error.to_string())
}

/// The code for a message that could not be built.
pub(super) const fn error_code_for(error: &synra_core::MessageError) -> ErrorCode {
    match error {
        // The user typed nothing, or typed something too large for one message. Both are about the argument, and the
        // second has its own code — the protocol has one for exactly this, and the client can offer "send as a file".
        synra_core::MessageError::Empty => ErrorCode::InvalidArgument,
        synra_core::MessageError::TooLong { .. } => ErrorCode::PayloadTooLarge,
        // The event name is a constant this build declares, so this is a contradiction inside the kernel rather than
        // anything the caller did.
        synra_core::MessageError::Envelope(_) | synra_core::MessageError::EventName(_) => {
            ErrorCode::Internal
        }
        _ => ErrorCode::Internal,
    }
}

/// The code for a transfer session that failed.
///
/// # Why a transfer failure is not one code
///
/// Because the user`s next step differs: bytes that did not match the digest are a corrupt transfer to retry or not, a
/// missing block is one that never finished, and a link failure is a network. One code for all three would leave the client
/// unable to say anything but the sentence the kernel wrote.
pub(super) const fn error_code_for_session(error: &synra_core::SessionError) -> ErrorCode {
    match error {
        // A transfer that did not verify is the code the protocol has for exactly this, and a client can act on it: the
        // partial file is discarded and a retry starts again.
        synra_core::SessionError::Transfer(synra_core::TransferError::DigestMismatch { .. })
        | synra_core::SessionError::Transfer(synra_core::TransferError::CompletionMismatch { .. }) => {
            ErrorCode::IntegrityMismatch
        }
        // A transfer that stopped with blocks owed never finished.
        synra_core::SessionError::Transfer(synra_core::TransferError::Incomplete { .. }) => {
            ErrorCode::TransferFailed
        }
        synra_core::SessionError::Link(synra_core::LinkError::Transport { .. }) => {
            ErrorCode::TransportNotOpen
        }
        synra_core::SessionError::Link(_) => ErrorCode::TransportNotOpen,
        synra_core::SessionError::WrongTransfer { .. }
        | synra_core::SessionError::BadProgress(_)
        | synra_core::SessionError::Payload { .. } => ErrorCode::ProtocolViolation,
        // Everything else is this kernel failing rather than the peer or the network, and `Internal` is the honest code for
        // a failure it cannot name.
        _ => ErrorCode::Internal,
    }
}
