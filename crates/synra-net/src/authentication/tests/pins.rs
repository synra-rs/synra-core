use std::io;
use std::sync::Arc;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use synra_protocol::DeviceId;

use super::{
    AuthenticatedStream, AuthenticationError, DeviceCredentials, IO_TIMEOUT, exchange, identity,
    now, request, sockets,
};
use crate::authentication::{credentials, handshake};

// A trusted certificate can act as a WebPKI trust anchor even though our device approval is for
// exactly one leaf. Exercise that distinction with a real signed child, not a made-up byte mismatch.
fn delegated_certificate() -> (DeviceCredentials, CertifiedKey) {
    let id = DeviceId::new();
    let params =
        rcgen::CertificateParams::new(vec![format!("{id}.synra.invalid")]).expect("params");
    let key = rcgen::KeyPair::generate().expect("key");
    let certificate = params.self_signed(&key).expect("self signed");
    let approved = DeviceCredentials::restore(id, certificate.der(), &key.serialize_der(), now())
        .expect("restore");
    let issuer = rcgen::Issuer::new(params.clone(), key);
    let child_key = rcgen::KeyPair::generate().expect("child key");
    let child = params.signed_by(&child_key, &issuer).expect("signed child");
    let certified = CertifiedKey::from_der(
        vec![child.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(child_key.serialize_der())),
        &rustls::crypto::ring::default_provider(),
    )
    .expect("certified child key");
    (approved, certified)
}

fn raw_server(config: rustls::ServerConfig, socket: std::net::TcpStream) -> io::Result<()> {
    let mut connection = ServerConnection::new(Arc::new(config)).expect("server");
    let mut socket = socket;
    connection.complete_io(&mut socket).map(|_| ())
}

#[test]
fn outgoing_authentication_requires_synra_alpn_from_the_server() {
    let client = identity();
    let server = identity();
    let mut config =
        handshake::server(&server, &[client.public_identity().clone()]).expect("server config");
    config.alpn_protocols.clear();
    let (outgoing, incoming) = sockets();
    let worker = std::thread::spawn(move || raw_server(config, incoming));
    let result =
        AuthenticatedStream::connect(outgoing, &client, server.public_identity(), IO_TIMEOUT);
    assert!(matches!(result, Err(AuthenticationError::Rejected(_))));
    // The TLS handshake itself succeeded; admission fails at the application protocol boundary.
    worker.join().expect("server").expect("TLS handshake");
}

#[test]
fn outgoing_authentication_rejects_an_unapproved_signed_descendant() {
    let client = identity();
    let (approved, child) = delegated_certificate();
    let mut config =
        handshake::server(&approved, &[client.public_identity().clone()]).expect("server config");
    config.cert_resolver = Arc::new(SingleCertAndKey::from(child));
    let (outgoing, incoming) = sockets();
    let worker = std::thread::spawn(move || raw_server(config, incoming));
    let result =
        AuthenticatedStream::connect(outgoing, &client, approved.public_identity(), IO_TIMEOUT);
    assert!(
        matches!(result, Err(AuthenticationError::Rejected(reason)) if reason == "peer certificate is not pinned")
    );
    worker
        .join()
        .expect("server")
        .expect("standard TLS accepted the signed descendant");
}

#[test]
fn incoming_authentication_rejects_an_unapproved_signed_descendant() {
    let server = identity();
    let (approved, child) = delegated_certificate();
    let peer = server.public_identity().clone();
    let mut config = handshake::client(&approved, &peer).expect("client config");
    config.client_auth_cert_resolver = Arc::new(SingleCertAndKey::from(child));
    let result = exchange(server, vec![approved.public_identity().clone()], |socket| {
        let connection = ClientConnection::new(
            Arc::new(config),
            credentials::server_name(peer.device_id()).expect("name"),
        )
        .expect("client");
        request(&mut StreamOwned::new(connection, socket))
    });
    assert!(!result.admitted);
    assert!(
        matches!(result.server, Err(AuthenticationError::Rejected(reason)) if reason == "peer certificate is not pinned")
    );
    assert!(result.client.is_err());
}
