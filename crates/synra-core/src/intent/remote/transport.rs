use super::*;

/// Sends one envelope and, when `wait` is given, reads the one answer the same connection carries.
///
/// # Why the link is a parameter
///
/// Because dialling is the host's business — the window and the daemon reach a peer through different identity and
/// metrics paths — but what counts as an answer is not. This is the part with the decisions in it: an `INTENT_RESULT` is
/// the answer, any other event is a protocol mistake rather than a slow action, and a timeout is **not** a failed
/// dispatch. A second copy in a host would be a second answer to those three questions.
///
/// # Returns
///
/// `Some(reply)` for an `INTENT_RESULT`, `None` when there is nothing to apply — a timeout, or no wait at all. A timeout
/// leaves the intent dispatching: the action may still be running over there, and the listener applies a late answer.
///
/// # Errors
///
/// [`SynraError`] with `TransportNotOpen` when the write or the read fails, and `InvalidArgument` when the peer answers
/// with an event that is not an intent result.
pub fn exchange(
    link: &mut PeerLink,
    outbound: &Outbound,
    wait: Option<Duration>,
) -> Result<Option<Envelope>, SynraError> {
    send(link, outbound)?;
    receive(link, wait)
}

/// Writes one envelope, without waiting for an answer.
///
/// # Errors
///
/// [`SynraError`] with `TransportNotOpen` when the link refuses the write.
pub fn send(link: &mut PeerLink, outbound: &Outbound) -> Result<(), SynraError> {
    link.send(&outbound.envelope).map_err(|error| {
        SynraError::new(
            ErrorCode::TransportNotOpen,
            format!("the envelope could not be written: {error}"),
        )
    })
}

/// Reads the one answer the same connection carries, then says goodbye.
///
/// # Why this is separate from [`send`]
///
/// Because a host that counts what it sent has to do it **between** the two: the daemon's `sent` counter is about
/// envelopes that went out, and a write that failed is not one. Splitting at the boundary the counter needs keeps the
/// decision about what an answer is in one place without giving the counter a second description.
///
/// # Returns
///
/// `Some(reply)` for an `INTENT_RESULT`, `None` when there is nothing to apply — a timeout, or no wait at all.
///
/// # Errors
///
/// [`SynraError`] with `TransportNotOpen` when the read fails, and `InvalidArgument` when the peer answers with an event
/// that is not an intent result.
pub fn receive(
    link: &mut PeerLink,
    wait: Option<Duration>,
) -> Result<Option<Envelope>, SynraError> {
    let answer = if let Some(wait) = wait {
        // The link's own deadline is the negotiated session timeout, which is far longer than one action's budget.
        // `wait` is the caller's own deadline and the reason this override exists.
        link.set_read_timeout(Some(wait));
        match link.receive() {
            Ok(reply) => {
                // ★ A peer that answers with something else is a protocol mistake, not a slow action. Saying so is what
                // stops an unexpected event from being silently treated as "still running".
                if reply.event.as_str() != events::INTENT_RESULT {
                    return Err(SynraError::new(
                        ErrorCode::InvalidArgument,
                        format!(
                            "it answered with {} instead of an intent result",
                            reply.event
                        ),
                    ));
                }
                Some(reply)
            }
            // ★ Not a failure: the action may still be running over there. The intent stays dispatching and the listener
            // applies a late answer.
            Err(LinkError::TimedOut) => None,
            Err(error) => {
                return Err(SynraError::new(
                    ErrorCode::TransportNotOpen,
                    format!("the answer could not be read: {error}"),
                ));
            }
        }
    } else {
        None
    };

    // The goodbye is best-effort: the answer has already been read, and failing to announce that the connection is
    // closing does not change what the user was told.
    let _ = link.bye(if wait.is_some() {
        "intent answered"
    } else {
        "intent dispatched"
    });
    Ok(answer)
}
