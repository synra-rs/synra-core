//! 配对写下的那一行，写的是**对端**，不是自己。
//!
//! # 为什么值得单独一条集成测试
//!
//! 这个方向错了两次：先是答复信封写成"发问者发给自己"，再是本机把对端身份当成了自己的。
//! 两次单测都过，因为它们两边用的是同一个 `DeviceId`——方向反了也看不出来。
//!
//! 所以这里用**两个不同的 id**，并断言记录里出现的是对端、不是本机。

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use synra_protocol::ids::DeviceId;
use std::path::Path;
use synra_protocol::session::PlatformKind;

fn prepare(dir: &Path) {
    let mut db = synra_store::SynraDb::open(&dir.join(synra_store::DB_FILE_NAME)).expect("opens");
    db.migrate().expect("migrates");
}

#[test]
fn the_row_names_the_peer_and_never_this_device() {
    let dir = tempfile::tempdir().expect("a temp dir");
    prepare(dir.path());
    let this_device = DeviceId::new();
    let peer = DeviceId::new();

    let wrote = synra_core::pairing_record::record_paired(
        dir.path(),
        peer,
        "Pixel",
        PlatformKind::Android,
        Some("192.168.0.9:47820".to_owned()),
        1_000,
    );
    assert!(wrote, "the row is written");

    let db = synra_store::SynraDb::open(&dir.path().join(synra_store::DB_FILE_NAME))
        .expect("the database opens");
    let rows = db.paired_devices().expect("the rows are readable");

    assert_eq!(rows.len(), 1, "one pairing, one row");
    assert_eq!(rows[0].device_id, peer.to_string(), "记录的是对端");
    assert_ne!(rows[0].device_id, this_device.to_string(), "不是本机");
    assert_eq!(rows[0].display_name, "Pixel");
    assert_eq!(rows[0].platform, "android");
    assert!(rows[0].features.is_empty(), "配对没有能力交集可写");
}

#[test]
fn a_second_peer_adds_a_second_row() {
    let dir = tempfile::tempdir().expect("a temp dir");
    prepare(dir.path());
    let first = DeviceId::new();
    let second = DeviceId::new();

    for (peer, name) in [(first, "Pixel"), (second, "Laptop")] {
        assert!(synra_core::pairing_record::record_paired(
            dir.path(),
            peer,
            name,
            PlatformKind::Desktop,
            None,
            1_000,
        ));
    }

    let db = synra_store::SynraDb::open(&dir.path().join(synra_store::DB_FILE_NAME))
        .expect("the database opens");
    let rows = db.paired_devices().expect("the rows are readable");

    assert_eq!(rows.len(), 2, "两台设备，两行");
    let ids: Vec<&str> = rows.iter().map(|row| row.device_id.as_str()).collect();
    assert!(ids.contains(&first.to_string().as_str()));
    assert!(ids.contains(&second.to_string().as_str()));
}
