use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use super::*;
use crate::identity::Identity;
use synra_store::secrets::{MemoryBackend, SecretBackendKind};

mod recovery;
#[cfg(windows)]
mod windows;

const NOW: u64 = 1_790_000_000;

#[test]
fn native_network_startup_refuses_an_ephemeral_database_before_enrollment() {
    let mut db = SynraDb::open_in_memory().unwrap();
    db.migrate().unwrap();
    let db = Arc::new(Mutex::new(db));
    let profile = crate::peer::LocalPeer::new(
        DeviceId::new(),
        "Ephemeral",
        synra_protocol::session::PlatformKind::Desktop,
        "0.1.0",
    );
    assert!(matches!(
        initialize_native_network(Arc::clone(&db), profile, NOW),
        Err(NetworkStartupError::EphemeralDatabase)
    ));
    assert!(db.lock().device_credential().unwrap().is_none());
}
const NORMAL: u8 = 0;
const FAIL_BEFORE_WRITE: u8 = 1;
const FAIL_AFTER_WRITE: u8 = 2;
const CORRUPT_WRITE: u8 = 3;
const LOSE_WRITE: u8 = 4;
type Hook = Mutex<Option<Box<dyn FnOnce() + Send>>>;

struct FaultBackend {
    values: MemoryBackend,
    mode: AtomicU8,
    writes: AtomicUsize,
    before_set: Hook,
    before_get: Hook,
    kind: SecretBackendKind,
}

impl Default for FaultBackend {
    fn default() -> Self {
        Self {
            values: MemoryBackend::new(),
            mode: AtomicU8::new(NORMAL),
            writes: AtomicUsize::new(0),
            before_set: Mutex::new(None),
            before_get: Mutex::new(None),
            kind: SecretBackendKind::EncryptedFile,
        }
    }
}

fn run_hook(hook: &Hook) {
    let action = hook.lock().take();
    if let Some(action) = action {
        action();
    }
}

impl SecretBackend for FaultBackend {
    fn get(&self, key: &SecretKey) -> Result<Option<SecretBytes>, SecretError> {
        run_hook(&self.before_get);
        self.values.get(key)
    }
    fn set(&self, key: &SecretKey, value: &SecretBytes) -> Result<(), SecretError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        run_hook(&self.before_set);
        match self.mode.load(Ordering::SeqCst) {
            FAIL_BEFORE_WRITE => {
                return Err(SecretError::Backend("injected before write".to_owned()));
            }
            CORRUPT_WRITE => {
                return self
                    .values
                    .set(key, &SecretBytes::new(b"corrupt key".to_vec()));
            }
            LOSE_WRITE => return Ok(()),
            _ => {}
        }
        self.values.set(key, value)?;
        if self.mode.load(Ordering::SeqCst) == FAIL_AFTER_WRITE {
            return Err(SecretError::Backend("injected after write".to_owned()));
        }
        Ok(())
    }
    fn delete(&self, key: &SecretKey) -> Result<(), SecretError> {
        self.values.delete(key)
    }
    // This is a fault-injection double, not a real encrypted backend. Native persistence is tested separately.
    fn kind(&self) -> SecretBackendKind {
        self.kind
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    path: std::path::PathBuf,
    db: Arc<Mutex<SynraDb>>,
    id: DeviceId,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("identity.sqlite");
        let mut db = SynraDb::open(&path).expect("database");
        db.migrate().expect("migrate");
        let id = Identity::load(&db, "test", 1).expect("identity").device_id;
        Self {
            _directory: directory,
            path,
            db: Arc::new(Mutex::new(db)),
            id,
        }
    }
    fn record(&self) -> DeviceCredentialRecord {
        self.db
            .lock()
            .device_credential()
            .expect("marker")
            .expect("enrolled marker")
    }
}

fn key(credentials: &DeviceCredentials) -> SecretKey {
    SecretKey::device_identity(*credentials.public_identity().fingerprint())
}

#[test]
fn load_never_implicitly_enrolls_and_memory_backend_is_refused() {
    let fixture = Fixture::new();
    let backend = FaultBackend::default();
    assert!(matches!(
        load(&fixture.db, &backend, fixture.id, NOW),
        Err(CredentialError::NotEnrolled)
    ));
    for result in [
        load(&fixture.db, &MemoryBackend::new(), fixture.id, NOW),
        enroll(&fixture.db, &MemoryBackend::new(), fixture.id, NOW),
    ] {
        assert!(matches!(result, Err(CredentialError::EphemeralBackend)));
    }
    assert!(
        fixture
            .db
            .lock()
            .device_credential()
            .expect("read")
            .is_none()
    );
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn enrolling_twice_reuses_the_same_certificate_and_key() {
    let fixture = Fixture::new();
    let backend = FaultBackend::default();
    let first = enroll(&fixture.db, &backend, fixture.id, NOW).expect("enroll");
    let second = enroll(&fixture.db, &backend, fixture.id, NOW).expect("reuse");
    assert_eq!(first.public_identity(), second.public_identity());
    assert_eq!(first.private_key_der(), second.private_key_der());
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
    assert!(fixture.record().ready());
}

#[test]
fn missing_or_replaced_private_keys_do_not_trigger_regeneration() {
    for missing in [true, false] {
        let fixture = Fixture::new();
        let backend = FaultBackend::default();
        let credentials = enroll(&fixture.db, &backend, fixture.id, NOW).expect("enroll");
        let before = fixture.record();
        if missing {
            backend.delete(&key(&credentials)).expect("remove key");
        } else {
            let other = DeviceCredentials::generate(fixture.id, NOW).expect("other key");
            backend
                .values
                .set(
                    &key(&credentials),
                    &SecretBytes::new(other.private_key_der().to_vec()),
                )
                .expect("replace key");
        }
        for result in [
            load(&fixture.db, &backend, fixture.id, NOW),
            enroll(&fixture.db, &backend, fixture.id, NOW),
        ] {
            if missing {
                assert!(matches!(result, Err(CredentialError::MissingKey)));
            } else {
                assert!(matches!(result, Err(CredentialError::InvalidCredential(_))));
            }
        }
        assert_eq!(fixture.record(), before);
        assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn switching_secret_backend_does_not_create_or_migrate_an_identity() {
    let fixture = Fixture::new();
    let original = FaultBackend::default();
    enroll(&fixture.db, &original, fixture.id, NOW).expect("enroll");
    let replacement = FaultBackend {
        kind: SecretBackendKind::WindowsCredential,
        ..FaultBackend::default()
    };
    assert!(matches!(
        load(&fixture.db, &replacement, fixture.id, NOW),
        Err(CredentialError::BackendChanged)
    ));
    assert_eq!(replacement.writes.load(Ordering::SeqCst), 0);
}

#[test]
fn secret_io_runs_without_the_database_lock() {
    let fixture = Fixture::new();
    let backend = FaultBackend::default();
    let during_set = Arc::clone(&fixture.db);
    *backend.before_set.lock() = Some(Box::new(move || {
        assert!(during_set.try_lock().is_some());
    }));
    let during_get = Arc::clone(&fixture.db);
    *backend.before_get.lock() = Some(Box::new(move || {
        assert!(during_get.try_lock().is_some());
    }));
    enroll(&fixture.db, &backend, fixture.id, NOW).expect("enroll");
}

#[test]
fn an_unenrolled_identity_with_existing_pairings_cannot_adopt_a_new_key() {
    let fixture = Fixture::new();
    fixture
        .db
        .lock()
        .pair_device(&synra_store::sqlite::Paired {
            device_id: DeviceId::new().to_string(),
            display_name: "old peer".to_owned(),
            platform: "test".to_owned(),
            features: "[]".to_owned(),
            link_token: "old generation".to_owned(),
            address: None,
            paired_at_ms: 1,
        })
        .expect("old pairing");
    let backend = FaultBackend::default();
    assert!(matches!(
        enroll(&fixture.db, &backend, fixture.id, NOW),
        Err(CredentialError::EnrollmentRefused)
    ));
    assert_eq!(backend.writes.load(Ordering::SeqCst), 0);
    assert!(
        fixture
            .db
            .lock()
            .device_credential()
            .expect("marker")
            .is_none()
    );
}
