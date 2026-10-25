//! Routing hints wrap the existing full-certificate invitation without granting trust.

use super::PairingServiceError;
use synra_net::authentication::PeerIdentity;
use synra_net::authentication::pairing::{decode_invitation, encode_invitation};

const REPLY_PREFIX: &str = "synra-pair-reply:1:";

pub(super) fn reply(identity: &PeerIdentity, port: u16) -> Result<String, PairingServiceError> {
    Ok(format!(
        "{REPLY_PREFIX}{port}:{}",
        encode_invitation(identity)?
    ))
}

pub(super) fn parse_reply(
    input: &str,
    now_seconds: u64,
) -> Result<(PeerIdentity, u16), PairingServiceError> {
    if input.len()
        > synra_net::authentication::pairing::MAX_INVITATION_BYTES + REPLY_PREFIX.len() + 6
    {
        return Err(PairingServiceError::InvalidReply);
    }
    let (port, identity) = input
        .strip_prefix(REPLY_PREFIX)
        .and_then(|body| body.split_once(':'))
        .ok_or(PairingServiceError::InvalidReply)?;
    let port: u16 = port
        .parse()
        .map_err(|_| PairingServiceError::InvalidReply)?;
    if port == 0 {
        return Err(PairingServiceError::InvalidReply);
    }
    Ok((decode_invitation(identity, now_seconds)?, port))
}
