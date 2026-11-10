use super::datagram::{
    DeviceAnnouncement, DiscoveryError, MAGIC_SEPARATOR, OFFLINE_MAGIC, OfflineAnnouncement,
    QUERY_MAGIC,
};

/// Builds a query datagram.
///
/// # Errors
///
/// [`DiscoveryError`] if the announcement is not usable.
pub fn encode_query(device: &DeviceAnnouncement) -> Result<Vec<u8>, DiscoveryError> {
    device.validate()?;
    let body = serde_json::to_string(device).map_err(|error| DiscoveryError::Malformed {
        kind: "query",
        detail: error.to_string(),
    })?;
    Ok(format!("{QUERY_MAGIC}{MAGIC_SEPARATOR}{body}").into_bytes())
}

/// Builds a response datagram, which carries no marker.
///
/// # Errors
///
/// [`DiscoveryError`] if the announcement is not usable.
pub fn encode_response(device: &DeviceAnnouncement) -> Result<Vec<u8>, DiscoveryError> {
    device.validate()?;
    serde_json::to_vec(device).map_err(|error| DiscoveryError::Malformed {
        kind: "response",
        detail: error.to_string(),
    })
}

/// Builds an offline announcement datagram.
///
/// # Errors
///
/// [`DiscoveryError`] if the announcement is not usable.
pub fn encode_offline(offline: &OfflineAnnouncement) -> Result<Vec<u8>, DiscoveryError> {
    offline.validate()?;
    let body = serde_json::to_string(offline).map_err(|error| DiscoveryError::Malformed {
        kind: "offline",
        detail: error.to_string(),
    })?;
    Ok(format!("{OFFLINE_MAGIC}{MAGIC_SEPARATOR}{body}").into_bytes())
}
