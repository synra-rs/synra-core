use super::*;
use crate::{device_credentials, identity::Identity};
use std::net::{TcpListener, TcpStream};
use synra_net::authentication::pairing::{decode_invitation, encode_invitation};
use synra_net::authentication::{AuthenticatedStream, DeviceCredentials};
use synra_protocol::DeviceId;
use synra_store::secrets::{
    MemoryBackend, SecretBackend, SecretBackendKind, SecretBytes, SecretError, SecretKey,
};

mod business;
mod failures;
mod lifecycle;

const TIMEOUT: Duration = Duration::from_secs(3);

// Persistence failure tests target SQLite; this double supplies keys only during fixture enrollment.
// It is not evidence of a real encrypted-file secret backend.
struct TestSecrets(MemoryBackend);

impl SecretBackend for TestSecrets {
    fn get(&self, key: &SecretKey) -> Result<Option<SecretBytes>, SecretError> {
        self.0.get(key)
    }
    fn set(&self, key: &SecretKey, value: &SecretBytes) -> Result<(), SecretError> {
        self.0.set(key, value)
    }
    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        self.0.delete(key)
    }
    fn kind(&self) -> SecretBackendKind {
        SecretBackendKind::EncryptedFile
    }
}

struct Device {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    db: Arc<Mutex<SynraDb>>,
    credentials: DeviceCredentials,
    now_ms: i64,
}

impl Device {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("device.sqlite");
        let mut db = SynraDb::open(&path).expect("database");
        db.migrate().expect("migrations");
        let now_ms = synra_store::sqlite::now_ms();
        let id = Identity::load(&db, "peer", now_ms)
            .expect("identity")
            .device_id;
        let db = Arc::new(Mutex::new(db));
        let credentials = device_credentials::enroll(
            &db,
            &TestSecrets(MemoryBackend::new()),
            id,
            u64::try_from(now_ms / 1000).expect("clock"),
        )
        .expect("enrollment");
        Self {
            _directory: directory,
            path,
            db,
            credentials,
            now_ms,
        }
    }

    fn id(&self) -> DeviceId {
        self.credentials.public_identity().device_id()
    }

    fn approvals(&self) -> Vec<PeerApproval> {
        approved_peers(
            &self.db,
            &self.credentials,
            u64::try_from(self.now_ms / 1000).unwrap(),
        )
        .expect("approvals")
    }

    fn reopen(&self, read_only: bool) {
        let db = if read_only {
            SynraDb::open_read_only(&self.path)
        } else {
            SynraDb::open(&self.path)
        }
        .expect("reopen");
        *self.db.lock() = db;
    }

    fn unpair(&self, peer: &Self) {
        assert!(
            self.db
                .lock()
                .unpair_device(&peer.id().to_string())
                .expect("unpair")
        );
    }
}

fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
    let outgoing = TcpStream::connect_timeout(&listener.local_addr().unwrap(), TIMEOUT).unwrap();
    let incoming = listener.accept().expect("accept").0;
    (outgoing, incoming)
}

fn tasks(left: &Device, right: &Device) -> (PairingTask, PairingTask) {
    let (outgoing, incoming) = sockets();
    let invitation = |device: &Device| {
        decode_invitation(
            &encode_invitation(device.credentials.public_identity()).unwrap(),
            u64::try_from(device.now_ms / 1000).unwrap(),
        )
        .unwrap()
    };
    let approved_left = invitation(left);
    let approved_right = invitation(right);
    let (client, server) = std::thread::scope(|scope| {
        let server = scope.spawn(|| {
            PairingChannel::accept(incoming, &right.credentials, &approved_left, TIMEOUT).unwrap()
        });
        let client =
            PairingChannel::connect(outgoing, &left.credentials, &approved_right, TIMEOUT).unwrap();
        (client, server.join().unwrap())
    });
    (
        PairingTask::begin(Arc::clone(&left.db), client, left.now_ms).unwrap(),
        PairingTask::begin(Arc::clone(&right.db), server, right.now_ms).unwrap(),
    )
}

fn pair(left: &Device, right: &Device) -> (PeerApproval, PeerApproval) {
    let (client, server) = tasks(left, right);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| server.finish(true, TIMEOUT, || right.now_ms));
        let local = client
            .finish(true, TIMEOUT, || left.now_ms)
            .expect("local grant");
        (local, worker.join().unwrap().expect("peer grant"))
    })
}

fn business(left: &Device, right: &Device) -> (AuthenticatedStream, AuthenticatedStream) {
    let (outgoing, incoming) = sockets();
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            AuthenticatedStream::accept(
                incoming,
                &right.credentials,
                &[left.credentials.public_identity().clone()],
                TIMEOUT,
            )
            .unwrap()
        });
        let local = AuthenticatedStream::connect(
            outgoing,
            &left.credentials,
            right.credentials.public_identity(),
            TIMEOUT,
        )
        .unwrap();
        (local, worker.join().unwrap())
    })
}
