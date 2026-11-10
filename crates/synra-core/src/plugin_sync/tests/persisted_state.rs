use super::super::*;
use super::plugin;

#[test]
fn a_table_loads_what_the_database_remembers() {
    // ★ 两张表回答同一个问题（谁持有什么），一张在内存里、一张在磁盘上。
    // 在此之前它们之间没有路：一个从库里读出行的宿主没有地方放它读到的东西。
    let rows = [
        synra_store::records::SyncRow {
            plugin_id: "@acme/chat".to_owned(),
            peer_device: "22222222-2222-4222-8222-222222222222".to_owned(),
            version: "1.2.0".to_owned(),
            digest: "sha256-abc".to_owned(),
            synced_at_ms: 2_000,
        },
        // 而这一行是**接收端**写的形状：摘要来自文件证明过的东西，版本是空的。
        synra_store::records::SyncRow {
            plugin_id: "@acme/chat".to_owned(),
            peer_device: "33333333-3333-4333-8333-333333333333".to_owned(),
            version: String::new(),
            digest: "sha256-def".to_owned(),
            synced_at_ms: 3_000,
        },
    ];
    let table = SyncTable::from_rows(&rows);
    let plugin_id = plugin("@acme/chat");

    let sender = table
        .state_of(
            &plugin_id,
            "22222222-2222-4222-8222-222222222222"
                .parse()
                .expect("a device"),
        )
        .expect("the sender's row");
    assert_eq!(sender.version.as_deref(), Some("1.2.0"));
    assert_eq!(sender.digest.as_deref(), Some("sha256-abc"));
    assert!(sender.has_it());

    // ★ 而空版本变成 `None` 而不是 `Some("")` —— 后者会被读成「对端持有版本 ''」这个断言，
    // 而 `has_it()` 正是那个会被答错的问题。
    let receiver = table
        .state_of(
            &plugin_id,
            "33333333-3333-4333-8333-333333333333"
                .parse()
                .expect("a device"),
        )
        .expect("the receiver's row");
    assert_eq!(receiver.version, None, "an empty version read as a claim");
    assert_eq!(receiver.digest.as_deref(), Some("sha256-def"));
    // ★ 而**这一轮把它修好了**。第一版断言写的是 `assert!(receiver.has_it())`，它在上一轮失败了 ——
    // 因为 `has_it` 当时是 `self.version.is_some()`，而这一行的版本是空的。
    //
    // 那是一个真缺陷：接收端写下的这一行（摘要来自文件证明、版本为空）说的是
    // 「这个对端持有这些字节」，而旧答案会读成「它没有这个插件」——
    // 于是下一次同步会把同一个包**每一轮都再推一遍**。
    assert!(receiver.has_it(), "a digest is evidence of holding it");
}

#[test]
fn a_row_this_build_cannot_read_is_skipped_rather_than_fatal() {
    // 标识来自一台可能跑着别的构建的设备。一张整体拒绝装载的表会把**其余的历史**一起带走。
    let rows = [
        synra_store::records::SyncRow {
            plugin_id: "not a plugin id".to_owned(),
            peer_device: "22222222-2222-4222-8222-222222222222".to_owned(),
            version: "1.0.0".to_owned(),
            digest: "sha256-abc".to_owned(),
            synced_at_ms: 1_000,
        },
        synra_store::records::SyncRow {
            plugin_id: "@acme/chat".to_owned(),
            peer_device: "22222222-2222-4222-8222-222222222222".to_owned(),
            version: "1.2.0".to_owned(),
            digest: "sha256-def".to_owned(),
            synced_at_ms: 1_000,
        },
    ];
    let table = SyncTable::from_rows(&rows);

    // 坏的那一行没了，而好的那一行还在。
    let state = table.state_of(
        &plugin("@acme/chat"),
        "22222222-2222-4222-8222-222222222222"
            .parse()
            .expect("a device"),
    );
    assert_eq!(
        state.and_then(|state| state.version.as_deref()),
        Some("1.2.0")
    );
}

#[test]
fn the_two_faces_of_one_question_agree() {
    // ★ `SyncTable`（内存）与 `sync_records`（SQLite）回答同一个问题：**谁持有什么**。
    //
    // ★ 而它们**不是**重复，理由与第 157 轮写下的那个不同 —— 那个理由是错的：
    // 它说内存的那张是给「没有 SQLite 的宿主」用的，而 `synra-core` 从第 136 轮起就依赖 `synra-store`
    // （`SyncRecord::to_row` 返回 store 的行类型）。所以这里没有那种宿主。
    //
    // 真正的理由是：一个是纯逻辑、一个是持久化，而**没有任何东西保证两边一致**。
    // 这条测试就是那个保证 —— 同一组事实写进库，再装进内存的那张，两边的答案必须一样。
    //
    // ★ 而它同时钉住第 162 轮修过的语义：**摘要也算「持有」**。库里那一行的版本是空的
    // （接收端写下的形状：摘要来自文件证明，而一次 `Decision` 不带版本），
    // 而两个实现都必须把它读成「有」，否则下一次同步会把同一个包再推一遍。
    let mut db = synra_store::SynraDb::open_in_memory().expect("opens");
    db.migrate().expect("migrates");
    let peer = "22222222-2222-4222-8222-222222222222";
    db.record_sync("@acme/chat", peer, "1.2.0", "sha256-abc", 2_000)
        .expect("records");
    // 而这一行是接收端的形状：版本空，摘要真。
    db.record_sync(
        "@acme/chat",
        "33333333-3333-4333-8333-333333333333",
        "",
        "sha256-def",
        3_000,
    )
    .expect("records");

    // 磁盘那一侧。
    let rows = db.sync_records().expect("reads");
    assert_eq!(rows.len(), 2);

    // 而内存那一侧从同一批行装起来。
    let table = SyncTable::from_rows(&rows);
    let plugin_id = plugin("@acme/chat");

    for row in &rows {
        let device = row.peer_device.parse().expect("a device id");
        let state = table
            .state_of(&plugin_id, device)
            .expect("the same peer is known");
        // 版本：库里的空串在两边都必须是「没有版本」，而不是「版本是空串」。
        let expected = if row.version.is_empty() {
            None
        } else {
            Some(row.version.as_str())
        };
        assert_eq!(
            state.version.as_deref(),
            expected,
            "the two faces disagree about {}",
            row.peer_device
        );
        assert_eq!(state.digest.as_deref(), Some(row.digest.as_str()));
        // ★ 而两者都说「有」—— 包括那个版本为空、只有摘要的行。
        assert!(state.has_it(), "the two faces disagree about holding it");
    }
}
