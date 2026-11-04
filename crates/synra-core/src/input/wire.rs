use crate::{PeerLink, input::Command};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use synra_protocol::PluginId;
use synra_protocol::envelope::{Envelope, OutboundSpec};
use synra_protocol::ids::{SessionId, TraceId};

pub(super) const OPEN: &str = "_synra.input.open";
pub(super) const ACCEPT: &str = "_synra.input.accept";
pub(super) const PACKET: &str = "_synra.input.packet";
pub(super) const ACK: &str = "_synra.input.ack";
pub(super) const CANCEL: &str = "_synra.input.cancel";
pub(super) const ERROR: &str = "_synra.input.error";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Open {
    pub(super) control_id: SessionId,
    pub(super) plugin_id: PluginId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Accepted {
    pub(super) session: SessionId,
    pub(super) generation: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Packet {
    pub(super) session: SessionId,
    pub(super) generation: i64,
    pub(super) sequence: u64,
    pub(super) commands: Vec<Command>,
}

pub(super) fn read<T: DeserializeOwned>(envelope: &Envelope) -> Result<T, String> {
    let body = envelope
        .payload_str()
        .ok_or_else(|| "missing input payload".to_owned())?;
    if body.len() > 16_384 {
        return Err("input payload too large".to_owned());
    }
    serde_json::from_str(body).map_err(|error| error.to_string())
}

pub(super) fn send<T: Serialize + ?Sized>(
    link: &mut PeerLink,
    event: &str,
    payload: &T,
) -> Result<(), String> {
    let spec = OutboundSpec {
        event: synra_protocol::event::EventName::parse(event).map_err(|error| error.to_string())?,
        target: link.peer(),
        from: link.local(),
        trace_id: TraceId::new(),
        sent_at_ms: synra_store::sqlite::now_ms(),
        ttl_ms: None,
    };
    let envelope = Envelope::outbound(spec, Some(payload)).map_err(|error| error.to_string())?;
    link.send(&envelope).map_err(|error| error.to_string())
}

pub(super) fn source_matches(link: &PeerLink, request: &Envelope) -> bool {
    request.from == link.peer() && request.target == link.local() && !request.from.is_nil()
}
