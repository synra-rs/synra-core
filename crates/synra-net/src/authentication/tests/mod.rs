use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use synra_protocol::DeviceId;

use super::{AuthenticatedStream, AuthenticationError, DeviceCredentials, PeerIdentity};

mod credentials;
mod pins;
mod rejection;
mod transport;

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const REQUEST: &[u8] = b"synra authenticated business payload 975b0be9";
const REPLY: &[u8] = b"synra authenticated response c6543a1d";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

fn identity() -> DeviceCredentials {
    DeviceCredentials::generate(DeviceId::new(), now()).expect("credentials")
}

fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let client = TcpStream::connect_timeout(&listener.local_addr().expect("address"), IO_TIMEOUT)
        .expect("connect");
    // A socket is queued before accept; no worker can be stranded waiting for a missing client.
    let (server, _) = listener.accept().expect("accept");
    for socket in [&client, &server] {
        socket
            .set_read_timeout(Some(IO_TIMEOUT))
            .expect("read timeout");
        socket
            .set_write_timeout(Some(IO_TIMEOUT))
            .expect("write timeout");
        socket.set_nodelay(true).expect("nodelay");
    }
    (client, server)
}

fn request(stream: &mut (impl Read + Write)) -> io::Result<()> {
    stream.write_all(REQUEST)?;
    stream.flush()?;
    let mut reply = vec![0; REPLY.len()];
    stream.read_exact(&mut reply)?;
    assert_eq!(reply, REPLY);
    Ok(())
}

struct Exchange {
    server: Result<(), AuthenticationError>,
    client: io::Result<()>,
    admitted: bool,
}

fn exchange(
    local: DeviceCredentials,
    peers: Vec<PeerIdentity>,
    client: impl FnOnce(TcpStream) -> io::Result<()>,
) -> Exchange {
    let (outgoing, incoming) = sockets();
    let admitted = Arc::new(AtomicBool::new(false));
    let handled = Arc::clone(&admitted);
    let worker = std::thread::spawn(move || -> Result<(), AuthenticationError> {
        let mut stream = AuthenticatedStream::accept(incoming, &local, &peers, IO_TIMEOUT)?;
        handled.store(true, Ordering::SeqCst);
        assert!(
            peers
                .iter()
                .any(|peer| peer.device_id() == stream.peer_device_id())
        );
        let mut request = vec![0; REQUEST.len()];
        stream
            .read_exact(&mut request)
            .map_err(|error| super::transport(&error))?;
        assert_eq!(request, REQUEST);
        stream
            .write_all(REPLY)
            .map_err(|error| super::transport(&error))?;
        stream.flush().map_err(|error| super::transport(&error))
    });
    let client = client(outgoing);
    Exchange {
        server: worker.join().expect("worker"),
        client,
        admitted: admitted.load(Ordering::SeqCst),
    }
}
