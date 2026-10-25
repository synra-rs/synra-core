use std::io::{Read, Write};

use serde::{Deserialize, Serialize};
use synra_protocol::DeviceId;

use super::{AuthenticatedStream, MAX_CONSENT_BYTES, PairingError, PeerIdentity};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Message {
    version: u8,
    from: DeviceId,
    target: DeviceId,
    binding: [u8; 32],
    confirmed: bool,
}

pub(super) fn exchange(
    stream: &mut AuthenticatedStream,
    local: &PeerIdentity,
    binding: [u8; 32],
    approved: bool,
) -> Result<(), PairingError> {
    let outgoing = Message {
        version: 1,
        from: local.device_id(),
        target: stream.peer_device_id(),
        binding,
        confirmed: approved,
    };
    let bytes = serde_json::to_vec(&outgoing)
        .map_err(|_| PairingError::Rejected("cannot encode consent"))?;
    if bytes.len() > MAX_CONSENT_BYTES {
        return Err(PairingError::Rejected("consent exceeds size limit"));
    }
    let size = u32::try_from(bytes.len())
        .map_err(|_| PairingError::Rejected("consent exceeds size limit"))?;
    stream
        .write_all(&size.to_be_bytes())
        .map_err(|error| io_error(&error))?;
    stream.write_all(&bytes).map_err(|error| io_error(&error))?;
    stream.flush().map_err(|error| io_error(&error))?;
    if !approved {
        return Err(PairingError::LocalDeclined);
    }
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .map_err(|error| io_error(&error))?;
    let len = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| PairingError::Rejected("invalid consent length"))?;
    if len == 0 || len > MAX_CONSENT_BYTES {
        return Err(PairingError::Rejected("consent exceeds size limit"));
    }
    let mut bytes = vec![0; len];
    stream
        .read_exact(&mut bytes)
        .map_err(|error| io_error(&error))?;
    let message: Message = serde_json::from_slice(&bytes)
        .map_err(|_| PairingError::Rejected("invalid consent record"))?;
    if message.version != 1
        || message.from != stream.peer_device_id()
        || message.target != local.device_id()
        || message.binding != binding
    {
        return Err(PairingError::Rejected(
            "consent does not match this session",
        ));
    }
    if !message.confirmed {
        return Err(PairingError::PeerDeclined);
    }
    Ok(())
}

fn io_error(error: &std::io::Error) -> PairingError {
    super::super::transport(error).into()
}
