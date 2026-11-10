//! 配对的那张桌子：一次只摆一份请求，人来决定它的下场。
//!
//! # 为什么是一个状态机，而不是几个布尔
//!
//! 配对的每一步都依赖上一步：只有**发起过**才谈得上取消，只有**收到过**才谈得上接受，
//! 而「接受」之后那份请求必须立刻消失——否则同一个人可以点两次「接受」，第二次落在已经写完的记录上，
//! 或者更糟，落在另一个人的请求上。
//!
//! 把这些写成 `Option` 与 `bool` 的组合，读的人要先在脑子里跑一遍三态表才能确认某个分支不可达；
//! 写成枚举之后，不可达的那一格**不存在**。
//!
//! # 它不认识数据库，也不认识 socket
//!
//! 这一层只回答「这个人点了之后，该发生什么」。写 `paired_devices` 与发帧都是调用方的事，
//! 因此这里每一条规矩都能在没有链路的测试里被验证，而不是只能在两台机器前试。
use std::time::Duration;

mod desk;
mod model;
mod service;

pub use model::{Ask, Desk, Offer, Outcome, Phase, Refused};
pub use service::{Decision, Service};

/// A pairing request expires when nobody answers it.
pub const PAIR_REQUEST_TTL: Duration = Duration::from_secs(120);

#[cfg(test)]
use std::time::Instant;
#[cfg(test)]
use synra_protocol::ids::DeviceId;
#[cfg(test)]
use synra_protocol::pairing::PairCode;
#[cfg(test)]
use synra_protocol::session::PlatformKind;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod service_tests;

#[cfg(test)]
mod dial_tests;

#[cfg(test)]
mod sink_tests;
