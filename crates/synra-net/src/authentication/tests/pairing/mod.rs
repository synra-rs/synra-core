use super::*;
use crate::authentication::pairing::{
    MAX_INVITATION_BYTES, MutualConsent, PairingChannel, PairingError, decode_invitation,
    encode_invitation,
};

mod rejection;

fn channels(
    left: &DeviceCredentials,
    right: &DeviceCredentials,
) -> (PairingChannel, PairingChannel) {
    let (outgoing, incoming) = sockets();
    // Model the trusted out-of-band transfer, then drive TLS using the parsed public invitations.
    let approved_left = decode_invitation(
        &encode_invitation(left.public_identity()).expect("local invitation"),
        now(),
    )
    .expect("verify local invitation");
    let approved_right = decode_invitation(
        &encode_invitation(right.public_identity()).expect("remote invitation"),
        now(),
    )
    .expect("verify remote invitation");
    std::thread::scope(|scope| {
        let server = scope.spawn(move || {
            PairingChannel::accept(incoming, right, &approved_left, IO_TIMEOUT)
                .expect("pairing server")
        });
        let client = PairingChannel::connect(outgoing, left, &approved_right, IO_TIMEOUT)
            .expect("pairing client");
        (client, server.join().expect("server"))
    })
}

fn consent(left: PairingChannel, right: PairingChannel) -> (MutualConsent, MutualConsent) {
    let server = std::thread::spawn(move || right.confirm(true, IO_TIMEOUT));
    let left = left.confirm(true, IO_TIMEOUT).expect("local consent");
    let right = server.join().expect("server").expect("remote consent");
    (left, right)
}

#[test]
fn public_invitations_roundtrip_and_pin_the_exact_certificate() {
    let credentials = identity();
    let text = encode_invitation(credentials.public_identity()).expect("invitation");
    assert!(text.is_ascii());
    assert!(text.len() < MAX_INVITATION_BYTES);
    assert_eq!(
        decode_invitation(&text, now()).expect("decode"),
        *credentials.public_identity()
    );
    let (_, rest) = text.split_once(':').expect("prefix");
    let (_, rest) = rest.split_once(':').expect("version");
    let (_, certificate) = rest.split_once(':').expect("id");
    let substituted = format!("synra-pair:1:{}:{certificate}", DeviceId::new());
    assert!(decode_invitation(&substituted, now()).is_err());
    assert!(decode_invitation(&text, now() + 4000 * 86_400).is_err());
}

#[test]
fn invitation_boundaries_reject_untrusted_data_before_use() {
    for text in [
        "".to_owned(),
        "synra-pair:2:other".to_owned(),
        "synra-pair:1:missing".to_owned(),
        "synra-pair:1:not-a-uuid:AA".to_owned(),
        "非ASCII".to_owned(),
        "x".repeat(MAX_INVITATION_BYTES + 1),
        format!("synra-pair:1:{}:invalid==", DeviceId::new()),
        format!("synra-pair:1:{}:AA", DeviceId::new()),
    ] {
        assert!(decode_invitation(&text, now()).is_err(), "input accepted");
    }
}

#[test]
fn both_users_consent_on_the_same_tls_session_and_both_identities_are_preserved() {
    let left = identity();
    let right = identity();
    let (client, server) = channels(&left, &right);
    assert_eq!(client.peer_identity(), right.public_identity());
    assert_eq!(server.peer_identity(), left.public_identity());
    let (local, remote) = consent(client, server);
    assert_eq!(local.local_identity(), left.public_identity());
    assert_eq!(local.peer_identity(), right.public_identity());
    assert_eq!(remote.local_identity(), right.public_identity());
    assert_eq!(remote.peer_identity(), left.public_identity());
    assert_eq!(local.session_binding(), remote.session_binding());
    assert_ne!(local.session_binding(), &[0; 32]);
}

#[test]
fn a_reconnect_with_the_same_keys_has_a_different_consent_binding() {
    let left = identity();
    let right = identity();
    let (first, other) = channels(&left, &right);
    let (first, _) = consent(first, other);
    let (second, other) = channels(&left, &right);
    let (second, _) = consent(second, other);
    assert_ne!(first.session_binding(), second.session_binding());
}

#[test]
fn a_local_decline_closes_the_channel_without_issuing_mutual_evidence_on_either_side() {
    let (client, server) = channels(&identity(), &identity());
    let worker = std::thread::spawn(move || server.confirm(true, IO_TIMEOUT));
    assert!(matches!(
        client.confirm(false, IO_TIMEOUT),
        Err(PairingError::LocalDeclined)
    ));
    // Immediate cancellation can race the other side's write; a closed transport is also a refusal,
    // never a reason to return consent. The received negative-record case is tested independently.
    assert!(worker.join().expect("server").is_err());
}

#[test]
fn zero_consent_budget_consumes_the_channel_without_issuing_evidence() {
    let (client, server) = channels(&identity(), &identity());
    assert!(matches!(
        client.confirm(true, Duration::ZERO),
        Err(PairingError::Authentication(AuthenticationError::TimedOut))
    ));
    assert!(server.confirm(true, IO_TIMEOUT).is_err());
}

#[test]
fn an_expired_user_prompt_cannot_issue_evidence_even_with_a_live_authenticated_socket() {
    let (mut client, server) = channels(&identity(), &identity());
    client.expire_for_test();
    assert!(matches!(
        client.confirm(true, IO_TIMEOUT),
        Err(PairingError::Authentication(AuthenticationError::TimedOut))
    ));
    assert!(server.confirm(true, IO_TIMEOUT).is_err());
}

#[test]
fn local_cancel_does_not_wait_for_the_remote_user_to_answer() {
    let (client, server) = channels(&identity(), &identity());
    let started = std::time::Instant::now();
    assert!(matches!(
        client.confirm(false, IO_TIMEOUT),
        Err(PairingError::LocalDeclined)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(server.confirm(true, IO_TIMEOUT).is_err());
}

#[test]
fn a_changed_key_in_the_same_device_id_cannot_produce_mutual_consent() {
    let original = identity();
    let replacement = DeviceCredentials::generate(original.public_identity().device_id(), now())
        .expect("replacement key");
    let right = identity();
    let peer = right.public_identity().clone();
    let approved = original.public_identity().clone();
    let (outgoing, incoming) = sockets();
    let server = std::thread::spawn(move || {
        PairingChannel::accept(incoming, &right, &approved, IO_TIMEOUT)
            .and_then(|channel| channel.confirm(true, IO_TIMEOUT))
    });
    let result = PairingChannel::connect(outgoing, &replacement, &peer, IO_TIMEOUT)
        .and_then(|channel| channel.confirm(true, IO_TIMEOUT));
    assert!(result.is_err());
    assert!(server.join().expect("server").is_err());
}

#[test]
fn self_pairing_is_refused_and_the_consumed_raw_socket_is_closed() {
    let local = identity();
    let (outgoing, mut incoming) = sockets();
    assert!(matches!(
        PairingChannel::connect(outgoing, &local, local.public_identity(), IO_TIMEOUT),
        Err(PairingError::Rejected(_))
    ));
    assert_eq!(incoming.read(&mut [0; 1]).expect("closed"), 0);
}

#[test]
fn business_and_pairing_alpn_cannot_be_substituted_in_either_direction() {
    for pairing_server in [true, false] {
        let left = identity();
        let right = identity();
        let approved = left.public_identity().clone();
        let peer = right.public_identity().clone();
        let (outgoing, incoming) = sockets();
        let server = std::thread::spawn(move || {
            if pairing_server {
                PairingChannel::accept(incoming, &right, &approved, IO_TIMEOUT).is_err()
            } else {
                AuthenticatedStream::accept(incoming, &right, &[approved], IO_TIMEOUT).is_err()
            }
        });
        let refused = if pairing_server {
            AuthenticatedStream::connect(outgoing, &left, &peer, IO_TIMEOUT).is_err()
        } else {
            PairingChannel::connect(outgoing, &left, &peer, IO_TIMEOUT).is_err()
        };
        assert!(refused);
        assert!(server.join().expect("server"));
    }
}

#[test]
fn a_valid_certificate_too_large_for_an_invitation_is_not_truncated() {
    let id = DeviceId::new();
    let mut names = vec![format!("{id}.synra.invalid")];
    names.extend((0..100).map(|index| format!("unused-{index}.synra.invalid")));
    let params = rcgen::CertificateParams::new(names).expect("parameters");
    let key = rcgen::KeyPair::generate().expect("key");
    let certificate = params.self_signed(&key).expect("certificate");
    let peer =
        PeerIdentity::from_certificate(id, certificate.der(), now()).expect("valid identity");
    assert!(matches!(
        encode_invitation(&peer),
        Err(PairingError::InvalidInvitation(_))
    ));
}
