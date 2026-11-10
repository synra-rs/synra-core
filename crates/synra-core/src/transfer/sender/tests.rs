use super::*;

/// A real temporary file: `open` reads it and hashes it, so this cannot be faked.
fn a_file() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("a unique directory per test");
    let path = root.path().join("artifact.wasm");
    std::fs::write(&path, b"\0asm\x01\0\0\0the artifact").expect("writes");
    (root, path)
}

#[test]
fn a_bundle_announces_itself_as_one() {
    // ★ 在这一轮之前，`request()` 把 `kind` 与 `meta` 硬编码成附件 ——
    // 于是一个插件包会以一张截图的身份到达，而接收端**正是**据此决定它落在哪里、以及它是什么
    // （第 139 轮的 `bundle` 字段、第 151 轮的安装）。
    let (_root, path) = a_file();
    let plugin_id =
        synra_protocol::ids::PluginId::try_from("@acme/chat".to_owned()).expect("an id");
    let round = crate::plugin_sync::SyncRound {
        plugin_id: plugin_id.clone(),
        version: "1.2.0".to_owned(),
        session: synra_protocol::ids::SessionId::new(),
    };
    let sender = TransferSender::open_bundle(&path, 4, &round).expect("opens");
    let request = sender.request();

    assert_eq!(request.kind, TransferKind::PluginBundle);
    // ★ 而它现在也说得出是哪一轮 —— 在此之前 `request()` 把 `sync_session_id` 写死成 `None`，
    // 于是一个包到了对端是一个**没人能命名的轮次**，而接收端要回的结果没有东西可以回应。
    assert_eq!(
        request.sync_session_id,
        Some(round.session),
        "the round did not travel with the request"
    );
    match request.meta {
        TransferMeta::PluginBundle {
            plugin_id: announced,
            version,
        } => {
            assert_eq!(announced, plugin_id);
            assert_eq!(version, "1.2.0");
        }
        other => panic!("a bundle was announced as {other:?}"),
    }
}

#[test]
fn an_ordinary_file_is_still_an_attachment() {
    // 另一半。没有这一条，把默认值改错会让每一次普通发送都变成插件包 ——
    // 而那样的错在接收端看起来完全正常。
    let (_root, path) = a_file();
    let sender = TransferSender::open(&path, 4).expect("opens");

    assert_eq!(sender.request().kind, TransferKind::Attachment);
}
