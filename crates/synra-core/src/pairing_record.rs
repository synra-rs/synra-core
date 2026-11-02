//! 写下「认识这台设备了」。
//!
//! # 为什么单独一个文件
//!
//! 因为配对的两侧都要写这一行，而两侧写的**必须是同一个形状**：接收方从 `PairRequest` 拿到的字段，
//! 和发起方从自己发出的 `PairRequest` 拿到的字段，本来就是同一组。写两份实现的结果是迟早有一份少一个字段——
//! 而这种差异只会在用户某天发现「这台设备在我这里没有名字」时才暴露。
//!
//! # 为什么能力位是空的
//!
//! 因为配对请求里没有 `Hello` 协商出来的交集。假装有一份能力列表，比留空更糟：前者会让下一次同步
//! 按一个从未存在过的共识去做决定。

use std::path::Path;

use synra_protocol::ids::DeviceId;
use synra_protocol::session::PlatformKind;

/// 记录一台已配对的设备。
///
/// 写失败只返回 `false`，不返回错误：这条路走完之后连接还要用，而一行账目写不进去不该让两个人白配一次。
#[must_use]
pub fn record_paired(
    data_dir: &Path,
    device_id: DeviceId,
    display_name: &str,
    platform: PlatformKind,
    address: Option<String>,
    now_ms: i64,
) -> bool {
    let Ok(db) = synra_store::SynraDb::open(&data_dir.join(synra_store::DB_FILE_NAME)) else {
        return false;
    };
    let platform = match platform {
        PlatformKind::Android => "android",
        PlatformKind::Ios => "ios",
        _ => "desktop",
    };
    let record = synra_store::Paired {
        device_id: device_id.to_string(),
        display_name: display_name.to_owned(),
        platform: platform.to_owned(),
        features: "[]".to_owned(),
        address,
        paired_at_ms: now_ms,
    };
    db.pair_device(&record).is_ok()
}