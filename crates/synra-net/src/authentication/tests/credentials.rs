use super::{DeviceCredentials, PeerIdentity, identity, now};
use crate::authentication::MAX_CREDENTIAL_BYTES;
use sha2::{Digest, Sha256};
use synra_protocol::DeviceId;

#[test]
fn credentials_round_trip_without_changing_identity_or_fingerprint() {
    let local = identity();
    let peer = local.public_identity();
    let restored = DeviceCredentials::restore(
        peer.device_id(),
        peer.certificate_der(),
        local.private_key_der(),
        now(),
    )
    .expect("restore");
    assert_eq!(restored.public_identity(), peer);
    assert_eq!(restored.private_key_der(), local.private_key_der());
    assert_eq!(
        peer.fingerprint().as_slice(),
        Sha256::digest(peer.certificate_der()).as_slice()
    );
}

#[test]
fn certificate_cannot_be_reassigned_to_a_different_device_id() {
    let local = identity();
    assert!(
        PeerIdentity::from_certificate(
            DeviceId::new(),
            local.public_identity().certificate_der(),
            now()
        )
        .is_err()
    );
    assert!(
        DeviceCredentials::restore(
            DeviceId::new(),
            local.public_identity().certificate_der(),
            local.private_key_der(),
            now(),
        )
        .is_err()
    );
}

#[test]
fn restoring_copied_certificate_without_matching_private_key_fails() {
    let local = identity();
    let other = identity();
    assert!(
        DeviceCredentials::restore(
            local.public_identity().device_id(),
            local.public_identity().certificate_der(),
            other.private_key_der(),
            now(),
        )
        .is_err()
    );
    assert!(
        DeviceCredentials::restore(
            local.public_identity().device_id(),
            local.public_identity().certificate_der(),
            &[],
            now(),
        )
        .is_err()
    );
}

#[test]
fn malformed_and_oversized_credentials_fail_at_the_boundary() {
    let id = DeviceId::new();
    for bytes in [Vec::new(), vec![0; 32], vec![0; MAX_CREDENTIAL_BYTES + 1]] {
        assert!(PeerIdentity::from_certificate(id, &bytes, now()).is_err());
    }
    let local = identity();
    assert!(
        DeviceCredentials::restore(
            local.public_identity().device_id(),
            local.public_identity().certificate_der(),
            &vec![0; MAX_CREDENTIAL_BYTES + 1],
            now(),
        )
        .is_err()
    );
    assert!(DeviceCredentials::generate(DeviceId::new(), u64::MAX).is_err());
}

#[test]
fn expired_and_not_yet_valid_certificates_are_rejected() {
    let local = identity();
    let peer = local.public_identity();
    assert!(PeerIdentity::from_certificate(peer.device_id(), peer.certificate_der(), 0).is_err());
    assert!(
        PeerIdentity::from_certificate(
            peer.device_id(),
            peer.certificate_der(),
            now() + 3651 * 24 * 60 * 60,
        )
        .is_err()
    );
}
