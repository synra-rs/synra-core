//! Production command, native secret writeback and restart with independently owned fixture data.

use super::*;
use std::sync::Arc;
use synra_control::CredentialAction;
use synra_core::device_credentials::{DEVICE_IDENTITY_SERVICE, repair_fingerprint};
use synra_store::secrets::{SecretBackend, SecretKey, WindowsCredentialBackend};
use synra_testkit::authentication::NetworkFixture;

struct Cleanup(Arc<parking_lot::Mutex<synra_store::SynraDb>>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let record = self.0.lock().device_credential().unwrap().unwrap();
        let id = record.device_id().parse().unwrap();
        let public = synra_net::authentication::PeerIdentity::from_certificate(
            id,
            record.certificate(),
            now_ms() / 1000,
        )
        .unwrap();
        let backend = WindowsCredentialBackend::new(DEVICE_IDENTITY_SERVICE).unwrap();
        backend
            .delete(&SecretKey::device_identity(*public.fingerprint()))
            .unwrap();
    }
}

#[test]
fn production_native_repair_requires_displayed_confirmation_and_restarts_with_the_new_key() {
    let fixture = NetworkFixture::unpaired(synra_protocol::DeviceId::new(), "Repair").unwrap();
    let runtime = runtime_over(fixture.root(), Arc::clone(&fixture.shared_db));
    let _cleanup = Cleanup(Arc::clone(&fixture.shared_db));
    let before = runtime.credentials(&CredentialAction::Status).unwrap();
    let fingerprint = before["enrollment"]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(
        runtime
            .credentials(&CredentialAction::Repair {
                expected_fingerprint: "stale".to_owned(),
            })
            .is_err()
    );
    let repaired = runtime
        .credentials(&CredentialAction::Repair {
            expected_fingerprint: fingerprint.clone(),
        })
        .unwrap();
    assert_eq!(repaired["restartRequired"], true);
    assert!(runtime.db().paired_devices().unwrap().is_empty());
    assert_ne!(repaired["fingerprint"], fingerprint);
    let reopened = Arc::new(parking_lot::Mutex::new(fixture.open_connection().unwrap()));
    let profile = synra_core::LocalPeer::new(
        runtime.identity.device_id,
        "Repair",
        synra_protocol::session::PlatformKind::Desktop,
        "0.1.0",
    );
    let recovered = synra_core::device_credentials::initialize_native_network(
        Arc::clone(&reopened),
        profile,
        now_ms() / 1000,
    )
    .unwrap();
    let public = synra_net::authentication::pairing::decode_invitation(
        &recovered.pairing().invitation().unwrap(),
        now_ms() / 1000,
    )
    .unwrap();
    assert_eq!(
        repair_fingerprint(public.certificate_der()),
        repaired["fingerprint"]
    );
    assert!(
        runtime
            .credentials(&CredentialAction::Repair {
                expected_fingerprint: fingerprint
            })
            .is_err()
    );
    // The fixture's original backend is deliberately unavailable, so its public cleanup record stays queued.
    assert_eq!(
        runtime.credentials(&CredentialAction::Cleanup).unwrap()["remaining"],
        1
    );
}
