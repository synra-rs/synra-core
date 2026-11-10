use std::net::SocketAddr;
use synra_protocol::discovery::DeviceAnnouncement;
use synra_protocol::handshake::PROTOCOL_VERSION;
use super::super::HostError;
use super::{A, B, device, host};

#[test]
fn resolving_an_unknown_name_says_so_rather_than_dialling_nothing() {
    let (client, _db) = host(B, "Phone");
    match client.resolve("Nobody") {
        Err(HostError::NoSuchDevice { wanted }) => assert_eq!(wanted, "Nobody"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    // And an empty string is not a device name either.
    assert!(matches!(
        client.resolve("   "),
        Err(HostError::NoSuchDevice { .. })
    ));
}

#[test]
fn resolving_an_ambiguous_name_is_refused_rather_than_guessed() {
    // ★ Picking one would send a message to a device the user did not choose, and the sender would never know: the
    // message would arrive, and it would look deliberate. An identifier is the way to disambiguate.
    let (mut client, _db) = host(B, "Phone");
    for id in [A, "33333333-3333-4333-8333-333333333333"] {
        client.heard(
            &DeviceAnnouncement {
                device_id: device(id),
                display_name: "Laptop".to_owned(),
                protocol: PROTOCOL_VERSION,
                port: 47_100,
                platform: None,
                app_version: None,
                features: Vec::new(),
            },
            SocketAddr::from(([10, 0, 0, 5], 1)),
            1_000,
        );
    }

    match client.resolve("Laptop") {
        Err(HostError::AmbiguousName { name, matches }) => {
            assert_eq!(name, "Laptop");
            assert_eq!(matches, 2);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // And the identifier still works, which is what the message tells the user to use.
    assert_eq!(client.resolve(A).expect("resolves"), device(A));
}

#[test]
fn an_identifier_wins_over_a_name_that_happens_to_match_it() {
    // ★ An identifier is unambiguous by construction and a name is whatever the other device decided to call itself.
    // Checking identifiers first means a user who pasted an id gets the device they pasted rather than a device that
    // renamed itself to match.
    let (mut client, _db) = host(B, "Phone");
    client.heard(
        &DeviceAnnouncement {
            // A device whose *name* is another device's identifier.
            device_id: device("33333333-3333-4333-8333-333333333333"),
            display_name: A.to_owned(),
            protocol: PROTOCOL_VERSION,
            port: 47_100,
            platform: None,
            app_version: None,
            features: Vec::new(),
        },
        SocketAddr::from(([10, 0, 0, 5], 1)),
        1_000,
    );
    client.heard(
        &DeviceAnnouncement {
            device_id: device(A),
            display_name: "Real".to_owned(),
            protocol: PROTOCOL_VERSION,
            port: 47_100,
            platform: None,
            app_version: None,
            features: Vec::new(),
        },
        SocketAddr::from(([10, 0, 0, 6], 1)),
        1_000,
    );

    assert_eq!(client.resolve(A).expect("resolves"), device(A));
    // Case-insensitively too, because a user pasting a UUID may have a different case and nothing else it could mean.
    assert_eq!(
        client.resolve(&A.to_uppercase()).expect("resolves"),
        device(A)
    );
}
