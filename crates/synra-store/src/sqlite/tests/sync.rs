use crate::records::SyncLogRow;
use super::migrated;

#[test]
fn a_sync_record_round_trips() {
    let db = migrated();
    db.record_sync("@acme/chat", "device-b", "1.2.0", "sha256-abc", 2_000).expect("records");

    let rows = db.sync_records().expect("reads");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].plugin_id, "@acme/chat");
    assert_eq!(rows[0].peer_device, "device-b");
    assert_eq!(rows[0].version, "1.2.0");
    assert_eq!(rows[0].digest, "sha256-abc");
    assert_eq!(rows[0].synced_at_ms, 2_000);
}

#[test]
fn a_second_round_for_the_same_peer_corrects_the_row_rather_than_adding_one() {
    // ★ 表的主键是 (plugin_id, peer_device)，而这是正确的形状：这张表回答「对端已经有了吗」，
    // 而一台设备两行会让这个问题有两个答案。同步的历史是 `plugin_sync::SyncRecord` 的事。
    let db = migrated();
    db.record_sync("@acme/chat", "device-b", "1.0.0", "sha256-old", 1_000).expect("first");
    db.record_sync("@acme/chat", "device-b", "1.1.0", "sha256-new", 2_000).expect("second");

    let rows = db.sync_records().expect("reads");
    assert_eq!(rows.len(), 1, "a second round added a row: {rows:?}");
    assert_eq!(rows[0].version, "1.1.0");
    assert_eq!(rows[0].digest, "sha256-new");
    assert_eq!(rows[0].synced_at_ms, 2_000);

    // 而另一台设备是另一行，所以「谁已经有了」仍然是一台一行。
    db.record_sync("@acme/chat", "device-c", "1.1.0", "sha256-new", 2_500).expect("third");
    assert_eq!(db.sync_records().expect("reads").len(), 2);
}

#[test]
fn a_peer_that_was_asked_again_replaces_what_was_known() {
    // ★ 一次**活的答复**是完整的：它说的是「现在有哪些」，不是增量。一台设备卸载了一个插件之后，
    // 它的答复里就没有那一行 —— 而 upsert 看不见「没有」，旧行会留到永远，于是每次计划都认为对端还持有着它。
    let db = migrated();
    db.record_sync("@acme/chat", "device-b", "1.0.0", "sha256-old", 1_000).expect("first");
    db.record_sync("@acme/gone", "device-b", "1.0.0", "sha256-gone", 1_000).expect("second");
    // 另一台设备的话不受影响：这次问的是 device-b。
    db.record_sync("@acme/chat", "device-c", "1.0.0", "sha256-old", 1_000).expect("another peer");

    let held = [("@acme/chat".to_owned(), "1.1.0".to_owned(), "sha256-new".to_owned())];
    db.replace_sync_for_peer("device-b", &held, 2_000).expect("replaces");

    let rows = db.sync_records().expect("reads");
    assert_eq!(rows.len(), 2, "one row for each peer: {rows:?}");
    let b = rows.iter().find(|row| row.peer_device == "device-b").expect("device-b");
    assert_eq!(b.version, "1.1.0");
    assert_eq!(b.digest, "sha256-new");
    assert_eq!(b.synced_at_ms, 2_000);
    assert!(
        rows.iter().all(|row| row.plugin_id != "@acme/gone"),
        "the plugin device-b no longer has is gone from the table: {rows:?}"
    );
    let c = rows.iter().find(|row| row.peer_device == "device-c").expect("device-c");
    assert_eq!(c.version, "1.0.0", "the other peer's answer is untouched");
}

#[test]
fn a_refused_replacement_leaves_the_old_answer_alone() {
    // ★ 删除与插入属于同一个事务：一次失败的插入如果只回滚自己，对端就会变成「什么都没有」——
    // 那是这张表能给出的、代价最大的错误答案。同一插件两行会撞主键，正好用来让第二次插入失败。
    let db = migrated();
    db.record_sync("@acme/chat", "device-b", "1.0.0", "sha256-old", 1_000).expect("first");
    let duplicated = [
        ("@acme/chat".to_owned(), "1.1.0".to_owned(), "sha256-new".to_owned()),
        ("@acme/chat".to_owned(), "1.2.0".to_owned(), "sha256-newer".to_owned()),
    ];

    let refused = db.replace_sync_for_peer("device-b", &duplicated, 2_000);

    assert!(refused.is_err(), "a duplicate primary key was accepted");
    let rows = db.sync_records().expect("reads");
    assert_eq!(rows.len(), 1, "the delete was not rolled back: {rows:?}");
    assert_eq!(rows[0].version, "1.0.0", "the old answer survived");
}

fn a_log_row(sync_id: &str, plugin: &str, started_at_ms: i64, finished: bool) -> SyncLogRow {
    SyncLogRow {
        sync_id: sync_id.to_owned(),
        plugin_id: plugin.to_owned(),
        peer_device: "device-b".to_owned(),
        started_at_ms,
        finished_at_ms: if finished { Some(started_at_ms + 500) } else { None },
        document: format!("{{\"syncId\":\"{sync_id}\"}}"),
    }
}

#[test]
fn a_round_is_recorded_and_read_back_newest_first() {
    let db = migrated();
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, true)).expect("first");
    db.record_sync_log(&a_log_row("sync-2", "@acme/chat", 2_000, true)).expect("second");

    let rows = db.sync_log(None, 10).expect("reads");
    assert_eq!(rows.len(), 2, "{rows:?}");
    // 最新在前：历史页面看的是刚刚发生了什么，而不是最早发生了什么。
    assert_eq!(rows[0].sync_id, "sync-2");
    assert_eq!(rows[1].sync_id, "sync-1");
    assert_eq!(rows[0].document, "{\"syncId\":\"sync-2\"}");
    // 以及 `limit` 真的限制住。
    assert_eq!(db.sync_log(None, 1).expect("reads").len(), 1);
}

#[test]
fn a_round_that_is_still_running_has_no_finish_time() {
    // 可空列不能用 `required`：没有结束时间是**事实**，不是缺陷 —— 一轮同步在开始时先写一行。
    let db = migrated();
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, false)).expect("started");

    let rows = db.sync_log(None, 10).expect("reads");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].finished_at_ms, None);
    assert!(rows[0].document.contains("sync-1"));
}

#[test]
fn finishing_a_round_corrects_its_row_rather_than_adding_one() {
    // ★ 一轮写两次：开始时一次、结束时一次 —— 而第二次是**同一轮**，不是第二轮。
    // 两行会让历史把一轮显示两遍，其中一遍说它从未结束。
    let db = migrated();
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, false)).expect("started");
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, true)).expect("finished");

    let rows = db.sync_log(None, 10).expect("reads");
    assert_eq!(rows.len(), 1, "finishing added a row: {rows:?}");
    assert_eq!(rows[0].finished_at_ms, Some(1_500));
}

#[test]
fn the_history_can_be_asked_about_one_plugin() {
    // 这两个问题是历史页面真正要问的，所以它们是列；其余在 document 里，不必为查一次而解析每一行。
    let db = migrated();
    db.record_sync_log(&a_log_row("sync-1", "@acme/chat", 1_000, true)).expect("chat");
    db.record_sync_log(&a_log_row("sync-2", "@acme/notes", 2_000, true)).expect("notes");

    let chat = db.sync_log(Some("@acme/chat"), 10).expect("reads");
    assert_eq!(chat.len(), 1, "{chat:?}");
    assert_eq!(chat[0].plugin_id, "@acme/chat");
    assert_eq!(db.sync_log(None, 10).expect("reads").len(), 2);
}
