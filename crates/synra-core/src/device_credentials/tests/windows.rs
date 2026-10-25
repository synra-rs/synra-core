use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use synra_net::authentication::AuthenticatedStream;
use synra_store::secrets::WindowsCredentialBackend;

use super::*;

// Cleanup consults only public enrollment data, so it also removes a key if enrollment reports an
// error after the native store wrote it. It holds no DB connection across the simulated restart.
struct NativeCleanup {
    path: PathBuf,
    service: String,
}

impl Drop for NativeCleanup {
    fn drop(&mut self) {
        let Ok(db) = SynraDb::open_read_only(&self.path) else {
            return;
        };
        let Ok(Some(record)) = db.device_credential() else {
            return;
        };
        let Ok(backend) = WindowsCredentialBackend::new(&self.service) else {
            return;
        };
        let fingerprint: [u8; 32] = Sha256::digest(record.certificate()).into();
        let _ = backend.delete(&SecretKey::device_identity(fingerprint));
    }
}

#[test]
fn native_key_and_database_restart_restore_the_same_authenticated_identity() {
    let fixture = Fixture::new();
    let service = format!("synra-core-test-{}", fixture.id);
    let _cleanup = NativeCleanup {
        path: fixture.path.clone(),
        service: service.clone(),
    };
    let backend = WindowsCredentialBackend::new(&service).expect("native backend");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let credentials = enroll(&fixture.db, &backend, fixture.id, now).expect("native enrollment");
    let approved = credentials.public_identity().clone();
    let private_key = SecretBytes::new(credentials.private_key_der().to_vec());
    drop(credentials);
    drop(backend);
    drop(fixture.db);
    let reopened = Mutex::new(SynraDb::open(&fixture.path).expect("database restart"));
    let backend = WindowsCredentialBackend::new(&service).expect("backend restart");
    let restored = load(&reopened, &backend, fixture.id, now).expect("native recovery");
    assert_eq!(restored.public_identity(), &approved);
    assert_eq!(restored.private_key_der(), private_key.expose());
    for suffix in ["", "-wal", "-shm"] {
        let mut path = fixture.path.as_os_str().to_owned();
        path.push(suffix);
        let path = PathBuf::from(path);
        if path.exists() {
            let bytes = std::fs::read(path).expect("database bytes");
            assert!(
                !bytes
                    .windows(private_key.len())
                    .any(|window| window == private_key.expose()),
                "private key reached SQLite files"
            );
        }
    }
    let remote = DeviceCredentials::generate(DeviceId::new(), now).expect("remote identity");
    let remote_public = remote.public_identity().clone();
    let timeout = Duration::from_secs(3);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listen");
    let outgoing = TcpStream::connect_timeout(&listener.local_addr().expect("address"), timeout)
        .expect("connect");
    let (incoming, _) = listener.accept().expect("queued accept");
    for socket in [&outgoing, &incoming] {
        socket
            .set_read_timeout(Some(timeout))
            .expect("read timeout");
        socket
            .set_write_timeout(Some(timeout))
            .expect("write timeout");
    }
    let worker = std::thread::spawn(move || {
        let mut stream = AuthenticatedStream::accept(incoming, &remote, &[approved], timeout)
            .expect("authenticate persisted peer");
        let mut message = [0; 5];
        stream.read_exact(&mut message).expect("request");
        assert_eq!(&message, b"ready");
        stream.write_all(b"known").expect("response");
        stream.flush().expect("flush");
    });
    let mut stream = AuthenticatedStream::connect(outgoing, &restored, &remote_public, timeout)
        .expect("authenticated reconnect");
    assert_eq!(stream.peer_device_id(), remote_public.device_id());
    stream.write_all(b"ready").expect("request");
    stream.flush().expect("flush");
    let mut response = [0; 5];
    stream.read_exact(&mut response).expect("response");
    assert_eq!(&response, b"known");
    worker.join().expect("server");
    backend
        .delete(&key(&restored))
        .expect("simulate credential loss");
    assert!(matches!(
        load(&reopened, &backend, fixture.id, now),
        Err(CredentialError::MissingKey)
    ));
    assert!(matches!(
        enroll(&reopened, &backend, fixture.id, now),
        Err(CredentialError::MissingKey)
    ));
}
