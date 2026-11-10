use std::time::Instant;

use synra_protocol::ids::DeviceId;
use synra_protocol::pairing::PairCode;
use synra_protocol::session::PlatformKind;

/// 当前摆在桌上的东西。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// 什么都没发生。
    Idle,
    /// 本机发起了配对，正在等对方答复。码显示在本机。
    Waiting,
    /// 对端发起了配对，正在等本机的人决定。码显示在对方。
    Asked,
    /// 已有一方接受，记录已经交给调用方去写。
    Done,
}

/// 发起方看到的东西：码，以及这条请求什么时候失效。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    /// 要显示给本机用户的码。
    pub code: PairCode,
    /// 对端。
    pub peer: DeviceId,
    /// 对端自称的名称。
    pub peer_name: String,
    /// 对端平台。
    pub peer_platform: PlatformKind,
}

/// 接收方看到的东西：谁在问，以及要跟对方屏幕比对的码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    /// 对方屏幕上的码，本机要显示给用户。
    pub code: PairCode,
    /// 发起方。
    pub peer: DeviceId,
    /// 发起方自称的名称。
    pub peer_name: String,
    /// 发起方平台。
    pub peer_platform: PlatformKind,
}

/// 一个人做了一件事之后，调用方该做什么。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// 本机接受了对方的请求：给对端回 `PAIR_RESPONSE{accepted:true}`，然后**两侧各写一行**。
    Accepted {
        /// 对方。
        peer: DeviceId,
    },
    /// 本机拒绝了对方的请求：回 `PAIR_RESPONSE{accepted:false}`，不写任何记录。
    Declined {
        /// 对方。
        peer: DeviceId,
    },
    /// 本机撤回了自己的请求：给对端回 `PAIR_CANCEL`。
    Cancelled {
        /// 对方。
        peer: DeviceId,
    },
    /// 对端接受了本机的请求：写记录，不回复。
    Completed {
        /// 对方。
        peer: DeviceId,
    },
}

/// 为什么有人点了却什么也没发生。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// 桌上没有对应的东西（已经答复过、已经撤回、或从未发起）。
    NothingToAnswer,
    /// 已经有一份请求在桌上：同一时刻只能谈一件事。
    Busy,
    /// 对方已经被本机记录过。
    AlreadyPaired,
}

/// 一张桌子。
#[derive(Debug)]
pub struct Desk {
    pub(super) state: State,
}

#[derive(Debug)]
pub(super) enum State {
    Idle,
    Waiting { offer: Offer, expires_at: Instant },
    Asked { ask: Ask, expires_at: Instant },
    Done { accepted: bool, cancelled: bool },
}
