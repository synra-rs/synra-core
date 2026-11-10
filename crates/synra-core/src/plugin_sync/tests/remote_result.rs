use synra_protocol::ids::DeviceId;

use super::super::*;
use super::plugin;

use crate::messaging::SyncResult;

fn a_result(ok: bool, version: Option<&str>, activated: bool) -> SyncResult {
    SyncResult {
        ok,
        installed_version: version.map(str::to_owned),
        activated,
        error: if ok { None } else { Some("refused".to_owned()) },
    }
}

#[test]
fn a_successful_round_updates_what_the_other_device_has() {
    // ★ 这也是 `SyncTable::record` 的第一个**生产**调用者：在此之前只有测试在写这张表，
    // 所以「A 更新同步状态」这一步没有实现。
    let mut table = SyncTable::new();
    let laptop = DeviceId::new();

    table.apply_result(
        laptop,
        &plugin("@acme/chat"),
        &a_result(true, Some("1.2.0"), true),
        "sha256-pushed",
    );

    let state = table
        .state_of(&plugin("@acme/chat"), laptop)
        .expect("recorded");
    assert_eq!(state.version.as_deref(), Some("1.2.0"));
    // ★ 摘要来自发起端自己算的那个，而不是回复 —— 回复里根本没有摘要。
    assert_eq!(state.digest.as_deref(), Some("sha256-pushed"));
    assert!(state.active);
}

#[test]
fn a_failed_round_does_not_move_what_the_other_device_has() {
    // ★ 这一条才是这个函数存在的理由。一次失败的同步**没有**改变对端持有什么：
    // 写成「什么也没有」会让下一次推送判断成「它需要」而重复传输，
    // 写成「新版本」更糟 —— 表会声称对端有一个它从未收到的包。
    let mut table = SyncTable::new();
    let laptop = DeviceId::new();
    let id = plugin("@acme/chat");
    table.record(
        laptop,
        RemoteState {
            plugin_id: id.clone(),
            version: Some("1.0.0".to_owned()),
            digest: Some("old".to_owned()),
            active: true,
        },
    );

    table.apply_result(laptop, &id, &a_result(false, None, false), "sha256-pushed");

    let state = table.state_of(&id, laptop).expect("still recorded");
    assert_eq!(
        state.version.as_deref(),
        Some("1.0.0"),
        "a failure moved the table"
    );
    assert_eq!(state.digest.as_deref(), Some("old"));
    assert!(state.active);

    // 以及一个自称成功却没有版本的回复：自相矛盾，不更新好过记一个半真半假的状态。
    table.apply_result(laptop, &id, &a_result(true, None, true), "sha256-pushed");
    assert_eq!(
        table
            .state_of(&id, laptop)
            .expect("recorded")
            .version
            .as_deref(),
        Some("1.0.0")
    );
}
