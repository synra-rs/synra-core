//! First-pairing production commands without preseeded peer grants or an approved business link.

use super::*;
use std::sync::Arc;
use std::time::{Duration, Instant};
use synra_control::PairingAction;
use synra_protocol::pairing::{PairingPhase, PairingSnapshot};
use synra_testkit::authentication::NetworkFixture;

const LEFT: &str = "11111111-1111-4111-8111-111111111111";
const RIGHT: &str = "22222222-2222-4222-8222-222222222222";

fn fixture(id: &str) -> (Runtime, NetworkFixture) {
    let fixture = NetworkFixture::unpaired(id.parse().unwrap(), "Peer").unwrap();
    let runtime = runtime_over(fixture.root(), Arc::clone(&fixture.shared_db));
    let profile = synra_core::LocalPeer::new(
        runtime.identity.device_id,
        "Peer",
        synra_protocol::session::PlatformKind::Desktop,
        "0.1.0",
    );
    let network = synra_core::peer::authenticated::AuthenticatedPeer::new(
        Arc::clone(&fixture.shared_db),
        Arc::clone(&fixture.credentials),
        profile,
    )
    .unwrap();
    runtime.host.lock().configure_network(Ok(network));
    (runtime, fixture)
}

fn status(runtime: &Runtime) -> PairingSnapshot {
    serde_json::from_value(runtime.pairing(&PairingAction::Status).unwrap()).unwrap()
}

fn terminal(runtime: &Runtime) -> PairingSnapshot {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let state = status(runtime);
        if state.phase.is_terminal() {
            return state;
        }
        assert!(
            Instant::now() < deadline,
            "first pairing did not finish: {state:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn daemon_commands_pair_new_devices_and_persist_their_grants() {
    let (left, left_fixture) = fixture(LEFT);
    let (right, right_fixture) = fixture(RIGHT);
    assert!(left.db().paired_devices().unwrap().is_empty());
    assert!(right.db().paired_devices().unwrap().is_empty());
    let invitation = left.pairing(&PairingAction::Invite).unwrap();
    let response: PairingSnapshot = serde_json::from_value(
        right
            .pairing(&PairingAction::Listen {
                device: LEFT.to_owned(),
                invitation: invitation
                    .get("invitation")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
            })
            .unwrap(),
    )
    .unwrap();
    // Discovery chooses only the route, never the certificate or a grant.
    let announcement = synra_core::LocalPeer::new(
        RIGHT.parse().unwrap(),
        "Peer",
        synra_protocol::session::PlatformKind::Desktop,
        "0.1.0",
    )
    .announcement(1);
    left.host.lock().heard(
        &announcement,
        "127.0.0.1:1".parse().unwrap(),
        synra_store::sqlite::now_ms(),
    );
    left.pairing(&PairingAction::Connect {
        device: RIGHT.to_owned(),
        reply: response.reply.unwrap(),
    })
    .unwrap();
    assert_eq!(terminal(&left).phase, PairingPhase::Paired);
    assert_eq!(terminal(&right).phase, PairingPhase::Paired);
    for fixture in [&left_fixture, &right_fixture] {
        let db = fixture.open_connection().unwrap();
        assert_eq!(db.paired_devices().unwrap().len(), 1);
        let grant = db
            .trusted_peer_records(
                &fixture
                    .credentials
                    .public_identity()
                    .device_id()
                    .to_string(),
                fixture.credentials.public_identity().certificate_der(),
            )
            .unwrap();
        assert_eq!(grant.len(), 1);
    }
}

#[test]
fn a_daemon_cancel_invalidates_only_the_named_local_generation() {
    let (left, _left_fixture) = fixture(LEFT);
    let (right, _right_fixture) = fixture(RIGHT);
    let invitation = left.pairing(&PairingAction::Invite).unwrap();
    let listening: PairingSnapshot = serde_json::from_value(
        right
            .pairing(&PairingAction::Listen {
                device: LEFT.to_owned(),
                invitation: invitation
                    .get("invitation")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
            })
            .unwrap(),
    )
    .unwrap();
    assert!(
        right
            .pairing(&PairingAction::Cancel {
                request_id: synra_protocol::RequestId::new()
            })
            .is_err()
    );
    right
        .pairing(&PairingAction::Cancel {
            request_id: listening.request_id,
        })
        .unwrap();
    assert_eq!(terminal(&right).phase, PairingPhase::Cancelled);
    assert!(right.db().paired_devices().unwrap().is_empty());
}

#[test]
fn a_selected_device_cannot_be_paired_using_somebody_elses_invitation() {
    let (left, _left_fixture) = fixture(LEFT);
    let (right, _right_fixture) = fixture(RIGHT);
    let invitation = left.pairing(&PairingAction::Invite).unwrap();
    let error = right
        .pairing(&PairingAction::Listen {
            device: synra_protocol::DeviceId::new().to_string(),
            invitation: invitation
                .get("invitation")
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned(),
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotPaired);
    assert!(right.pairing(&PairingAction::Status).unwrap().is_null());
    assert!(right.db().paired_devices().unwrap().is_empty());
}

#[test]
fn cancellation_of_a_missing_task_does_not_claim_success() {
    let (runtime, _fixture) = fixture(LEFT);
    let error = runtime
        .pairing(&PairingAction::Cancel {
            request_id: synra_protocol::RequestId::new(),
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotPaired);
    assert!(runtime.db().paired_devices().unwrap().is_empty());
}
