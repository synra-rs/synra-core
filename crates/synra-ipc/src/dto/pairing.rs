//! 配对的三样东西：一条请求、一份快照、一个结果。
//!
//! # 为什么码是字符串
//!
//! 因为它是给人看的：`000042` 与 `42` 对人是两个不同的东西（一个能念、一个会被念错），
//! 而 JSON 里的 `42` 到了界面就没有前导零了。协议层存数值、这一层存六位文本，各自保存自己那边正确的形状。
//!
//! # 为什么快照里有「谁在配」
//!
//! 因为屏幕要能同时回答两个问题：我在等谁，以及是谁在等我。合成一个 `peer` 字段的结果，
//! 是接收方的弹窗永远显示「等待对方答复」——而那正是发起方的句子。

use serde::{Deserialize, Serialize};
use synra_protocol::ids::DeviceId;

/// 一次配对走到了哪一步。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PairingPhase {
    /// 什么都没发生。
    Idle,
    /// 本机发起，等对面答复。码在本机屏幕上。
    Waiting,
    /// 对面发起，等本机的人决定。码在对方屏幕上。
    Asked,
    /// 已有一方答复过，结果在 [`PairingSnapshot::outcome`]。
    Done,
}

/// 本机发起的那份请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingOffer {
    /// 要显示给本机用户的六位码。
    pub code: String,
    /// 对端。
    pub device_id: DeviceId,
    /// 对端自称的名称。
    pub display_name: String,
    /// 对端平台。
    pub platform: String,
}

/// 对端发起的那份请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingAsk {
    /// 对方屏幕上的六位码，本机要显示给用户。
    pub code: String,
    /// 发起方。
    pub device_id: DeviceId,
    /// 发起方自称的名称。
    pub display_name: String,
    /// 发起方平台。
    pub platform: String,
}

/// 这次配对最后是什么结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PairingOutcome {
    /// 对上了。
    Paired,
    /// 对面拒绝了。
    Refused,
    /// 本机撤回了。
    Cancelled,
    /// 两分钟没有人回答。
    TimedOut,
}

/// 配对屏幕要的全部状态，一次取回。
///
/// 一次而不是三次，理由与 [`crate::DevicesSnapshot`] 相同：分开取会渲染出三个互相矛盾的中间态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingSnapshot {
    /// 现在走到哪一步。
    pub phase: PairingPhase,
    /// 本机发起的请求，若正等着答复。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offer: Option<PairingOffer>,
    /// 对端发起的请求，若正等着本机的人决定。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ask: Option<PairingAsk>,
    /// 已答复的那次配对的结果。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<PairingOutcome>,
}

impl PairingSnapshot {
    /// 什么都没发生。
    #[must_use]
    pub const fn idle() -> Self {
        Self {
            phase: PairingPhase::Idle,
            offer: None,
            ask: None,
            outcome: None,
        }
    }
}