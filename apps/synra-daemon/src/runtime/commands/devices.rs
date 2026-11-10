use synra_control::Refusal;
use synra_protocol::error::ErrorCode;

use super::super::{Runtime, now_ms};

impl Runtime {
    pub(super) fn command_devices(
        &self,
        include_unpaired: bool,
        scan_ms: Option<u64>,
    ) -> Result<serde_json::Value, Refusal> {
        // ★ The scan is done **before** the table is read, and by the worker rather than here. Only the worker owns the
        // discovery socket, and a client that slept for the duration and then asked would get exactly the table it would
        // have got without asking — the sleep would look like a scan and be a delay.
        if let Some(scan_ms) = scan_ms.filter(|ms| *ms > 0) {
            self.scan(scan_ms);
        }

        // ★ Three sources, reported separately rather than merged. A paired device, a device merely heard on the network,
        // and this device are three different things to a user — and a list that put them together would present an
        // unauthenticated datagram as something the user had approved.
        let host = self.host.lock();
        let now = now_ms();

        // The paired devices come from the database, which is the recorded decision.
        let paired = self.db().paired_devices().map_err(|error| {
            Refusal::new(
                ErrorCode::Internal,
                format!("could not read the paired devices: {error}"),
            )
        })?;
        let mut paired_list: Vec<serde_json::Value> = Vec::new();
        for row in &paired {
            // The session is the proof the device is reachable *now*, as opposed to recorded once. A user asking for
            // devices is asking what they can act on, so the two are reported together.
            let device_id: synra_protocol::ids::DeviceId =
                row.device_id.parse().map_err(|error| {
                    Refusal::new(
                        ErrorCode::Internal,
                        format!(
                            "the stored device id {} is not a UUID: {error}",
                            row.device_id
                        ),
                    )
                })?;
            let session = host.state_of(device_id);
            paired_list.push(serde_json::json!({
                "deviceId": row.device_id,
                "displayName": row.display_name,
                "platform": row.platform,
                "blocked": row.blocked,
                "pairedAtMs": row.paired_at_ms,
                "lastSeenMs": row.last_seen_ms,
                // `null` when there is no session, which is different from a session that is closed — and the difference
                // is what tells a user whether the device is offline or was never reached.
                "linkState": session.map(|state| format!("{state:?}")),
            }));
        }

        // The candidates are what discovery heard, which is unauthenticated and therefore reported as its own list.
        let candidates: Vec<serde_json::Value> = if include_unpaired {
            host.discovery()
                .displayable(synra_core::millis_reading(now))
                .map(|candidate| {
                    serde_json::json!({
                        "deviceId": candidate.device_id.to_string(),
                        "displayName": candidate.display_name,
                        "address": candidate.address.to_string(),
                        "trust": format!("{:?}", candidate.trust),
                        "lastSeenMs": candidate.last_seen_ms,
                    })
                })
                .collect()
        } else {
            Vec::new()
        };

        Ok(serde_json::json!({
            // ★ Reported rather than omitted, so a client prints it. A user who runs `devices` because nothing works
            // needs to know which device they are running it *on* — that identifier is what the other end has recorded
            // against them.
            "self": {
                "deviceId": self.identity.device_id.to_string(),
                "displayName": self.identity.display_name,
                "platform": self.identity.platform,
            },
            "paired": paired_list,
            "found": candidates,
            "includeUnpaired": include_unpaired,
            "count": paired_list.len() + candidates.len(),
        }))
    }
}
