use crate::ids::DeviceId;
use crate::session::PlatformKind;

use super::{Feature, Hello, HelloAck, PROTOCOL_VERSION, SessionNonce};

fn hello() -> Hello {
    Hello {
        protocol: PROTOCOL_VERSION,
        device_id: DeviceId::new(),
        display_name: "laptop".to_owned(),
        platform: PlatformKind::Desktop,
        app_version: "1.0.0".to_owned(),
        nonce: SessionNonce(1),
        features: Feature::ALL.to_vec(),
        requires: Vec::new(),
        sequence: 1,
        endpoints: Vec::new(),
    }
}

fn accepted_ack(nonce: SessionNonce) -> HelloAck {
    HelloAck {
        protocol: PROTOCOL_VERSION,
        device_id: DeviceId::new(),
        display_name: "phone".to_owned(),
        platform: PlatformKind::Android,
        app_version: "1.0.0".to_owned(),
        nonce,
        features: Feature::ALL.to_vec(),
        requires: Vec::new(),
        refusal: None,
        sequence: 1,
        endpoints: Vec::new(),
    }
}

mod acknowledgment;
mod bounds;
mod features;
mod hello;
