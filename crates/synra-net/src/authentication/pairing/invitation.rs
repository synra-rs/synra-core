use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::{PairingError, PeerIdentity};

/// Maximum ASCII invitation size, small enough for the largest standard QR byte-mode payload.
pub const MAX_INVITATION_BYTES: usize = 2048;
const PREFIX: &str = "synra-pair:1:";

/// Encodes only the public device id and full certificate for trusted out-of-band transfer.
///
/// # Errors
/// Refuses a certificate whose full representation exceeds the invitation budget; never truncates.
pub fn encode_invitation(identity: &PeerIdentity) -> Result<String, PairingError> {
    let device_id = identity.device_id().to_string();
    let overhead = PREFIX.len() + device_id.len() + 1;
    if base64::encoded_len(identity.certificate_der().len(), false)
        .is_none_or(|length| length > MAX_INVITATION_BYTES.saturating_sub(overhead))
    {
        return Err(PairingError::InvalidInvitation("size limit exceeded"));
    }
    let invitation = format!(
        "{PREFIX}{device_id}:{}",
        URL_SAFE_NO_PAD.encode(identity.certificate_der())
    );
    Ok(invitation)
}

/// Parses an untrusted invitation and validates its full certificate, device name and validity.
///
/// This does not approve its provenance or grant trust. The host must obtain the entire invitation
/// through the intended peer's trusted display/transfer and ask the local user to confirm that source.
///
/// # Errors
/// Rejects unsupported versions, excessive input, invalid UUID/base64 and invalid or expired certificates.
pub fn decode_invitation(input: &str, now_seconds: u64) -> Result<PeerIdentity, PairingError> {
    if input.len() > MAX_INVITATION_BYTES || !input.is_ascii() {
        return Err(PairingError::InvalidInvitation(
            "size or encoding limit exceeded",
        ));
    }
    let body = input
        .strip_prefix(PREFIX)
        .ok_or(PairingError::InvalidInvitation("unsupported format"))?;
    let (device_id, certificate) = body
        .split_once(':')
        .ok_or(PairingError::InvalidInvitation("missing fields"))?;
    let device_id = device_id
        .parse()
        .map_err(|_| PairingError::InvalidInvitation("invalid device id"))?;
    let certificate = URL_SAFE_NO_PAD
        .decode(certificate)
        .map_err(|_| PairingError::InvalidInvitation("invalid certificate encoding"))?;
    PeerIdentity::from_certificate(device_id, &certificate, now_seconds).map_err(PairingError::from)
}
