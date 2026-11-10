//! Fixtures shared by kernel tests.

use std::path::PathBuf;

use synra_protocol::discovery::DeviceAnnouncement;
use synra_protocol::handshake::PROTOCOL_VERSION;
use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;
use tempfile::{Builder, TempDir};

use crate::host::Host;
use crate::identity::Identity;
use crate::peer::{Flags, LocalPeer};

pub(crate) fn temp_dir(tag: &str) -> TempDir {
    Builder::new().prefix(tag).tempdir().expect("a unique directory per test")
}

pub(crate) fn file(dir: &TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).expect("writes the test file");
    path
}

pub(crate) fn device(name: &str) -> DeviceId {
    name.parse().expect("a valid device id")
}

pub(crate) fn host(id: &str, name: &str) -> Host {
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    db.create_identity_if_absent(
        &synra_store::IdentityRow::from_columns(Some(id), Some(name), Some("test"), Some(1_000))
            .expect("identity row"),
    )
    .expect("initial identity");
    let identity = Identity::load(&db, "test", 1_000).expect("an identity");
    let local = LocalPeer::new(
        identity.device_id,
        identity.display_name.clone(),
        PlatformKind::Desktop,
        "0.1.0-test",
    );
    Host::with_flags(identity, local, Flags::no_timeout())
}

pub(crate) fn announcement(id: &str, name: &str, port: u16) -> DeviceAnnouncement {
    DeviceAnnouncement {
        device_id: device(id),
        display_name: name.to_owned(),
        protocol: PROTOCOL_VERSION,
        port,
        platform: Some(PlatformKind::Desktop),
        app_version: Some("0.1.0".to_owned()),
        features: Vec::new(),
    }
}
