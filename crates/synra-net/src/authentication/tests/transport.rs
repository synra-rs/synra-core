use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{
    AuthenticatedStream, DeviceCredentials, IO_TIMEOUT, REPLY, REQUEST, exchange, identity, now,
    request, sockets,
};

#[test]
fn restored_credentials_reconnect_through_both_production_entry_points() {
    let client = identity();
    let server = identity();
    let approved = server.public_identity().clone();
    let peers = vec![
        identity().public_identity().clone(),
        client.public_identity().clone(),
    ];
    let restored = DeviceCredentials::restore(
        client.public_identity().device_id(),
        client.public_identity().certificate_der(),
        client.private_key_der(),
        now(),
    )
    .expect("restore");
    let result = exchange(server, peers, |socket| {
        let mut stream = AuthenticatedStream::connect(socket, &restored, &approved, IO_TIMEOUT)
            .map_err(io::Error::other)?;
        assert_eq!(stream.peer_device_id(), approved.device_id());
        assert_eq!(stream.peer_identity(), &approved);
        request(&mut stream)
    });
    assert!(result.admitted);
    result.server.expect("accepted");
    result.client.expect("response");
}

#[test]
fn payloads_are_encrypted_on_actual_tcp_wires() {
    let client = identity();
    let server = identity();
    let approved = server.public_identity().clone();
    let peers = vec![client.public_identity().clone()];
    let (outgoing, proxy_incoming) = sockets();
    let (proxy_outgoing, incoming) = sockets();
    let wire = Arc::new(Mutex::new(Vec::new()));
    let forward = |mut source: std::net::TcpStream, mut destination: std::net::TcpStream| {
        let captured = Arc::clone(&wire);
        std::thread::spawn(move || {
            let mut bytes = [0; 8192];
            loop {
                match source.read(&mut bytes) {
                    Ok(0) => break,
                    Ok(count) => {
                        captured
                            .lock()
                            .expect("capture")
                            .extend_from_slice(&bytes[..count]);
                        if destination.write_all(&bytes[..count]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = destination.shutdown(Shutdown::Write);
        })
    };
    let to_server = forward(
        proxy_incoming.try_clone().expect("clone"),
        proxy_outgoing.try_clone().expect("clone"),
    );
    let to_client = forward(proxy_outgoing, proxy_incoming);
    let worker = std::thread::spawn(move || {
        let mut stream =
            AuthenticatedStream::accept(incoming, &server, &peers, IO_TIMEOUT).expect("accept");
        let mut payload = vec![0; REQUEST.len()];
        stream.read_exact(&mut payload).expect("request");
        assert_eq!(payload, REQUEST);
        stream.write_all(REPLY).expect("write");
        stream.flush().expect("flush");
    });
    let mut stream =
        AuthenticatedStream::connect(outgoing, &client, &approved, IO_TIMEOUT).expect("connect");
    request(&mut stream).expect("response");
    drop(stream);
    worker.join().expect("server");
    to_server.join().expect("forward");
    to_client.join().expect("reverse");
    let wire = wire.lock().expect("capture");
    assert!(!wire.is_empty());
    for payload in [REQUEST, REPLY] {
        assert!(!wire.windows(payload.len()).any(|window| window == payload));
    }
    drop(wire);
}

#[test]
fn socket_timeouts_are_restored_after_authentication() {
    let client = identity();
    let server = identity();
    let peer = server.public_identity().clone();
    let peers = vec![client.public_identity().clone()];
    let (outgoing, incoming) = sockets();
    let worker = std::thread::spawn(move || {
        let stream = AuthenticatedStream::accept(incoming, &server, &peers, Duration::from_secs(2))
            .expect("accept");
        assert_eq!(stream.read_timeout().expect("read"), Some(IO_TIMEOUT));
        assert_eq!(stream.write_timeout().expect("write"), Some(IO_TIMEOUT));
    });
    let stream = AuthenticatedStream::connect(outgoing, &client, &peer, Duration::from_secs(2))
        .expect("connect");
    assert_eq!(stream.read_timeout().expect("read"), Some(IO_TIMEOUT));
    assert_eq!(stream.write_timeout().expect("write"), Some(IO_TIMEOUT));
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read");
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .expect("set write");
    assert_eq!(
        stream.read_timeout().expect("read"),
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        stream.write_timeout().expect("write"),
        Some(Duration::from_secs(1))
    );
    worker.join().expect("server");
}
