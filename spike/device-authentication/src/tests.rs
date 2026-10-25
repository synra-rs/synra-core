use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ProtocolVersion, ServerConnection, StreamOwned};

use super::*;

const REQUEST: &[u8] = b"private synra business payload 975b0be9";
const REPLY: &[u8] = b"authenticated response c6543a1d";

// Captures actual socket writes, not TLS plaintext or a mock network.
struct CapturedSocket {
    socket: TcpStream,
    wire: Arc<Mutex<Vec<u8>>>,
}

impl Read for CapturedSocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.socket.read(bytes)
    }
}

impl Write for CapturedSocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.socket.write(bytes)?;
        self.wire
            .lock()
            .expect("wire")
            .extend_from_slice(&bytes[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

fn sockets() -> (CapturedSocket, CapturedSocket, Arc<Mutex<Vec<u8>>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let client = TcpStream::connect_timeout(
        &listener.local_addr().expect("address"),
        Duration::from_secs(3),
    )
    .expect("connect");
    // A connection is already queued; no worker waits for a client that might never connect.
    let (server, _) = listener.accept().expect("accept");
    let wire = Arc::new(Mutex::new(Vec::new()));
    let wrap = |socket: TcpStream| {
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("read deadline");
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .expect("write deadline");
        CapturedSocket {
            socket,
            wire: Arc::clone(&wire),
        }
    };
    (wrap(client), wrap(server), wire)
}

struct Exchange {
    client: io::Result<()>,
    server: io::Result<()>,
    wire: Vec<u8>,
    admitted: bool,
}

fn exchange(server: ServerConfig, client: Option<ClientConfig>) -> Exchange {
    let (client_socket, server_socket, wire) = sockets();
    let admitted = Arc::new(AtomicBool::new(false));
    let handled = Arc::clone(&admitted);
    let worker = std::thread::spawn(move || -> io::Result<()> {
        let connection = ServerConnection::new(Arc::new(server)).expect("server connection");
        let mut stream = StreamOwned::new(connection, server_socket);
        let mut request = vec![0; REQUEST.len()];
        // Receiving the complete request is the application boundary: rejected peers must never reach it.
        stream.read_exact(&mut request)?;
        handled.store(true, Ordering::SeqCst);
        assert_eq!(request, REQUEST);
        assert_eq!(
            stream.conn.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        );
        assert_eq!(stream.conn.alpn_protocol(), Some(b"synra/1".as_slice()));
        assert!(stream.conn.peer_certificates().is_some());
        stream.write_all(REPLY)?;
        stream.flush()
    });
    let client = match client {
        Some(config) => {
            let connection = ClientConnection::new(
                Arc::new(config),
                ServerName::try_from("synra.device").expect("name"),
            )
            .expect("client connection");
            let mut stream = StreamOwned::new(connection, client_socket);
            request(&mut stream).inspect(|()| {
                assert_eq!(
                    stream.conn.protocol_version(),
                    Some(ProtocolVersion::TLSv1_3)
                );
            })
        }
        None => request(&mut { client_socket }),
    };
    let server = worker.join().expect("bounded server");
    let wire = wire.lock().expect("wire").clone();
    Exchange {
        client,
        server,
        wire,
        admitted: admitted.load(Ordering::SeqCst),
    }
}

fn request(stream: &mut (impl Read + Write)) -> io::Result<()> {
    stream.write_all(REQUEST)?;
    stream.flush()?;
    let mut reply = vec![0; REPLY.len()];
    stream.read_exact(&mut reply)?;
    if reply != REPLY {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not an authenticated response",
        ));
    }
    Ok(())
}

fn refused(result: Exchange) {
    assert!(
        !result.admitted,
        "no rejected connection may reach the application boundary"
    );
    assert!(
        result.client.is_err(),
        "the client must not complete a business request"
    );
    assert!(
        result.server.is_err(),
        "the server must reject before accepting a business request"
    );
}

#[test]
fn persisted_credentials_reconnect_with_authenticated_encrypted_payloads() {
    let alice = Identity::generate().expect("alice");
    let bob = Identity::generate().expect("bob");
    let directory = tempfile::tempdir().expect("private test directory");
    let certificate = directory.path().join("certificate.der");
    let key = directory.path().join("key.pk8");
    std::fs::write(&certificate, alice.certificate.as_ref()).expect("save public identity");
    std::fs::write(&key, alice.key.secret_pkcs8_der()).expect("save private identity");
    let restored = Identity {
        certificate: CertificateDer::from(std::fs::read(certificate).expect("reopen certificate")),
        key: PrivatePkcs8KeyDer::from(std::fs::read(key).expect("reopen key")),
    };
    let result = exchange(
        server(&bob, alice.certificate()).expect("server"),
        Some(client(Some(&restored), bob.certificate()).expect("client")),
    );
    result.client.expect("client exchange");
    result.server.expect("server exchange");
    assert!(result.admitted);
    for secret in [REQUEST, REPLY] {
        assert!(
            !result
                .wire
                .windows(secret.len())
                .any(|bytes| bytes == secret),
            "payload is encrypted on the wire"
        );
    }
}

#[test]
fn a_replacement_server_key_is_refused_even_with_the_same_name() {
    let alice = Identity::generate().expect("alice");
    let bob = Identity::generate().expect("bob");
    let impostor = Identity::generate().expect("impostor");
    refused(exchange(
        server(&impostor, alice.certificate()).expect("server"),
        Some(client(Some(&alice), bob.certificate()).expect("client")),
    ));
}

#[test]
fn an_unpaired_client_key_is_refused_even_with_the_same_name() {
    let alice = Identity::generate().expect("alice");
    let bob = Identity::generate().expect("bob");
    let impostor = Identity::generate().expect("impostor");
    refused(exchange(
        server(&bob, alice.certificate()).expect("server"),
        Some(client(Some(&impostor), bob.certificate()).expect("client")),
    ));
}

#[test]
fn a_client_without_an_identity_is_refused() {
    let alice = Identity::generate().expect("alice");
    let bob = Identity::generate().expect("bob");
    refused(exchange(
        server(&bob, alice.certificate()).expect("server"),
        Some(client(None, bob.certificate()).expect("client")),
    ));
}

#[test]
fn plaintext_business_requests_cannot_downgrade_the_transport() {
    let alice = Identity::generate().expect("alice");
    let bob = Identity::generate().expect("bob");
    refused(exchange(
        server(&bob, alice.certificate()).expect("server"),
        None,
    ));
}

#[test]
fn an_older_tls_client_cannot_downgrade_the_transport() {
    let alice = Identity::generate().expect("alice");
    let bob = Identity::generate().expect("bob");
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("TLS 1.2 client")
            .with_root_certificates(roots(bob.certificate()).expect("root"))
            .with_client_auth_cert(vec![alice.certificate()], alice.key())
            .expect("identity");
    config.alpn_protocols = vec![b"synra/1".to_vec()];
    refused(exchange(
        server(&bob, alice.certificate()).expect("server"),
        Some(config),
    ));
}

#[test]
fn a_public_certificate_without_its_private_key_is_not_an_identity() {
    let alice = Identity::generate().expect("alice");
    let bob = Identity::generate().expect("bob");
    let forged = Identity {
        certificate: alice.certificate(),
        key: bob.key.clone_key(),
    };
    assert!(server(&forged, bob.certificate()).is_err());
    assert!(client(Some(&forged), bob.certificate()).is_err());
}
